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

;; Chunk 2: EIP-712 hash helpers (sha256 adapted; LE uint serial via buff-from-uinteger pad-left0)
(define-constant DOMAIN_NAME_STR (string-ascii "ERC-8001"))
(define-constant DOMAIN_VERSION_STR (string-ascii "1"))
(define-constant DOMAIN_NAME_HASH (sha256 DOMAIN_NAME_STR))
(define-constant DOMAIN_VERSION_HASH (sha256 DOMAIN_VERSION_STR))

(define-constant AGENT_INTENT_TYPE_STR
  (string-ascii
    "AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,bytes32 participantsHash)"
  )
)
(define-constant AGENT_INTENT_TYPEHASH (sha256 AGENT_INTENT_TYPE_STR))

(define-constant ACCEPTANCE_TYPE_STR
  (string-ascii
    "AcceptanceAttestation(bytes32 intentHash,address participant,uint64 nonce,uint64 expiry,bytes32 conditionsHash)"
  )
)
(define-constant ACCEPTANCE_TYPEHASH (sha256 ACCEPTANCE_TYPE_STR))

(define-constant SIG_PREFIX (concat (buff 1 0x19) (buff 1 0x01)))

(define-constant PAD_ZERO_12
  (buff 12
    0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00
  )
)

;; Private: buff20 -> buff32 pad-right 0x00 (EIP address equiv)
(define-private (address-to-buff32 (p principal))
  (concat (principal-hash160 p) PAD_ZERO_12)
)

;; Private: domain separator (sha256(nameH32 + versionH32 + chainId32LE + verifyingContract32))
(define-private (get-domain-separator)
  (let
    (
      (chain32 (buff-from-uinteger (chain-id) u32))
      (verifying32 (address-to-buff32 contract-caller))
    )
    (sha256
      (concat DOMAIN_NAME_HASH
        (concat DOMAIN_VERSION_HASH
          (concat chain32 verifying32)
        )
      )
    )
  )
)

;; Private: participants hash = sha256(concat(p1.hash160 || p2.hash160 || ...)) (EIP equiv)
(define-private (participants-to-hash (participants (list 20 principal)))
  (sha256
    (fold
      concat
      (map principal-hash160 participants)
      0x{}
    )
  )
)

;; Private: agent intent struct hash (sha256(typeH || fields serialized))
(define-private (intent-struct-hash
    (payload-hash (buff 32))
    (expiry uint)
    (nonce uint)
    (agent principal)
    (coord-type (buff 32))
    (coord-value uint)
    (part-hash (buff 32))
  )
  (sha256
    (concat AGENT_INTENT_TYPEHASH
      (concat payload-hash
        (concat
          (buff-from-uinteger expiry u8)
          (concat
            (buff-from-uinteger nonce u8)
            (concat
              (address-to-buff32 agent)
              (concat coord-type
                (concat
                  (buff-from-uinteger coord-value u32)
                  part-hash
                )
              )
            )
          )
        )
      )
    )
  )
)

;; Private: acceptance struct hash (sha256(typeH || intentH32 || part32 || nonce8 || expiry8 || cond32))
(define-private (acceptance-struct-hash
    (intent-hash (buff 32))
    (participant principal)
    (accept-nonce uint)
    (accept-expiry uint)
    (conditions (buff 32))
  )
  (sha256
    (concat ACCEPTANCE_TYPEHASH
      (concat intent-hash
        (concat
          (address-to-buff32 participant)
          (concat
            (buff-from-uinteger accept-nonce u8)
            (concat
              (buff-from-uinteger accept-expiry u8)
              conditions
            )
          )
        )
      )
    )
  )
)

;; Private: full acceptance EIP-712 digest for sig (sha256(1901 || domainSep || structH))
(define-private (acceptance-digest
    (intent-hash (buff 32))
    (participant principal)
    (accept-nonce uint)
    (accept-expiry uint)
    (conditions (buff 32))
  )
  (let
    (
      (domain-sep (get-domain-separator))
      (struct-h (acceptance-struct-hash intent-hash participant accept-nonce accept-expiry conditions))
    )
    (sha256 (concat SIG_PREFIX (concat domain-sep struct-h)))
  )
)

;; Public: propose new coordination intent (EIP proposeCoordination fields; tx-sender=agent, no sig/payload)
(define-public (propose-coordination (payload-hash (buff 32)) (expiry uint) (nonce uint) (coord-type (buff 32)) (coord-value uint) (participants (list 20 principal)))
  (let
    (
      (agent tx-sender)
      (now (stacks-block-time))
    )
    (asserts! (> expiry now) ERR_EXPIRED)
    (let
      (
        (prev-nonce (default-to u0 (map-get? agent-nonces {agent: agent})))
      )
      (asserts! (> nonce prev-nonce) ERR_NONCE_TOO_LOW)
      (asserts! (is-sorted-principals? participants) ERR_INVALID_PARTICIPANTS)
      (asserts! (contains-principal? participants agent) ERR_INVALID_PARTICIPANTS)
      (let
        (
          (part-hash (participants-to-hash participants))
          (intent-hash (intent-struct-hash payload-hash expiry nonce agent coord-type coord-value part-hash))
        )
        (asserts! (is-none (map-get? intents {intent-hash: intent-hash})) ERR_INVALID_PARTICIPANTS)
        (try! (map-insert intents {intent-hash: intent-hash}
          {
            agent: agent,
            expiry: expiry,
            nonce: nonce,
            coord-type: coord-type,
            coord-value: coord-value,
            participants: participants,
            status: PROPOSED,
            accept-count: u0
          }
        ))
        (map-set agent-nonces {agent: agent} nonce)
        (print {
          event: "CoordinationProposed",
          intent-hash: intent-hash,
          proposer: agent,
          coordination-type: coord-type,
          participant-count: (len participants),
          coordination-value: coord-value
        })
        (ok intent-hash)
      )
    )
  )
)

