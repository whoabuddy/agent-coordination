;; ERC-8001 Agent Coordination (Stacks SIP-XXX / EIP-8001 adapted)
;; Minimal multi-party coordination primitive using signed intents and acceptances.
;; Assumes standard principals (EOA-like agents); contract wallets via future ERC1271 equiv out-of-scope.
;; Uses sha256 (Clarity-native; equivalent to keccak for domain separation).
;; Max 20 participants (decidable cost ~O(20^2) worst).
;; Status lifecycle: None -> Proposed -> (Ready -> Executed) | Cancelled | Expired.

(define-constant NONE u0)
(define-constant PROPOSED u1)
(define-constant READY u2)
(define-constant EXECUTED u3)
(define-constant CANCELLED u4)
(define-constant EXPIRED u5)

(define-constant ERR_UNAUTHORIZED u100)
(define-constant ERR_NOT_FOUND u101)
(define-constant ERR_INVALID_STATE u102)
(define-constant ERR_INVALID_SIG u103)
(define-constant ERR_NOT_PARTICIPANT u104)
(define-constant ERR_ALREADY_ACCEPTED u105)
(define-constant ERR_EXPIRED u106)
(define-constant ERR_NONCE_TOO_LOW u107)
(define-constant ERR_INVALID_PARTICIPANTS u108)
(define-constant ERR_ACCEPT_EXPIRED u109)

;; Storage
(define-map intents 
    {intent-hash: (buff 32)}
    {
        agent: principal,
        expiry: uint,
        nonce: uint,
        coord-type: (buff 32),
        coord-value: uint,
        participants: (list 20 principal),
        status: uint,
        accept-count: uint
    }
)

(define-map agent-nonces {agent: principal} uint)

(define-map acceptances 
    {intent-hash: (buff 32), participant: principal}
    {accept-expiry: uint, conditions: (buff 32)}
)

;; Private: principal -> buff21 (v1 + hash160(20b); panics invalid/contract?)
(define-private (principal->buff21 (p principal))
    (let ((destruct (unwrap-panic (principal-destruct? p))))
        (concat (get version destruct) (get hash-bytes destruct))
    )
)

;; Private: principal -> hash160 buff20
(define-private (principal-hash160 (p principal))
    (get hash-bytes (unwrap-panic (principal-destruct? p)))
)

;; Private: plist contains? p (fold O(n))
(define-private (contains-principal? (plist (list 20 principal)) (p principal))
    (fold
        (lambda (x found) (or found (is-eq x p)))
        plist
        false
    )
)

;; Private: buff21 a < buff21 b strictly (lex byte cmp; false if == or >)
(define-private (buff21-lt? (a (buff 21)) (b (buff 21)))
    (let (
        (byte-cmp
            (fold
                (lambda (idx res)
                    (if (is-some res)
                        res
                        (let (
                            (byte-a (unwrap-panic (element-at? a idx)))
                            (byte-b (unwrap-panic (element-at? b idx)))
                        )
                            (cond
                                (< byte-a byte-b) (some true)
                                (> byte-a byte-b) (some false)
                                true none  ;; ==
                            )
                        )
                    )
                )
                (list 
                    u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
                    u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20
                )
                none
            )
        )
    )
        (match byte-cmp some-val some-val false)  ;; all == -> false (not strict <)
    )
)

;; Private: participants strictly ascending sorted by buff21 lex (implies unique, no dups)
;; Fails if len>20, any consecutive not <, or len>=2 no pairs.
(define-private (is-sorted-principals? (plist (list 20 principal)))
    (let ((n (len plist)))
        (if (> n u20)
            false
            (if (<= n u1)
                true  ;; 0/1 trivial
                (fold
                    (lambda (i sorted-so-far)
                        (if (not sorted-so-far)
                            false
                            (if (>= i (- n u1))
                                true  ;; no more pairs
                                (let (
                                    (curr (unwrap-panic (element-at? plist i)))
                                    (next (unwrap-panic (element-at? plist (+ i u1))))
                                    (curr-b (principal->buff21 curr))
                                    (next-b (principal->buff21 next))
                                )
                                    (buff21-lt? curr-b next-b)
                                )
                            )
                        )
                    )
                    (list 
                        u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
                        u10 u11 u12 u13 u14 u15 u16 u17 u18 u19
                    )
                    true
                )
            )
        )
    )
)

