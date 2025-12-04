;; ERC-8001 Agent Coordination (Stacks SIP-XXX / EIP-8001 port)
;; Minimal single-chain multi-party coordination: propose AgentIntent (tx-prove), accept via EIP-712 sigs.
;; Core state machine only (no exec logic; modules add). Standard principals; sha256/BE32 ABI-pack.
;; Ref: https://eips.ethereum.org/EIPS/eip-8001
;; Trait: IAgentCoordination (below); max 20 parts (O(20^2) decidable).
;; Usage ex: Propose w/ sorted participants (inc agent), off-chain sign accept-digest (nonce=0), execute w/ payload.
;; Test outline: Clarinet (propose/acceptN/ready/execute; cancel/expire edge; invalid sig/sort/nonce/expiry).

;; (define-trait IAgentCoordination
;;   (
    ;; Propose (tx-sender=agent; no sig; returns intentHash)
;;     (propose-coordination (buff 32) uint uint (buff 32) uint (list 20 principal)) (response (buff 32) uint)
    ;; Accept (tx-sender=participant; sig over acceptance-digest; returns all-accepted?)
;;     (accept-coordination (buff 32) uint (buff 32) (buff 65)) (response bool uint)
    ;; Execute (any; verify payload/sha256==payloadHash/all-fresh; returns (success result); state Executed)
;;     (execute-coordination (buff 32) (buff 1024) (buff 1024)) (response bool (buff 1024))
    ;; Cancel (agent pre-expiry/any post; reason opt; state Cancelled)
;;     (cancel-coordination (buff 32) (string-ascii 34)) (response bool uint)
    ;; Status (effective inc auto-Expired; accepted-by list)
 ;;    (get-coordination-status (buff 32)) (response
 ;;      {status: uint, agent: principal, participants: (list 20 principal), accepted-by: (list 20 principal), expiry: uint}
 ;;      uint)
    ;; Required = len(participants)
;;     (get-required-acceptances (buff 32)) (response uint uint)
    ;; Nonce (latest used)
;;     (get-agent-nonce (principal)) uint
;;   )
;; )

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
(define-constant ERR_PAYLOAD_HASH_MISMATCH u110)

;; Storage
(define-map intents 
    {intent-hash: (buff 32)}
    {
        agent: principal,
        payload-hash: (buff 32),
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
(define-private (principal-buff21 (p principal))
    (let ((destruct (unwrap-panic (principal-destruct? p))))
        (concat (get version destruct) (get hash-bytes destruct))
    )
)

;; Private: principal -> hash160 buff20
(define-private (principal-hash160 (p principal))
    (get hash-bytes (unwrap-panic (principal-destruct? p)))
)

;; Private: plist contains? p (fold O(n))
(define-private (contains-fold-step (elem principal) (accum {found: bool, target: principal}))
  {found: (or (get found accum) (is-eq elem (get target accum))), target: (get target accum)}
)

(define-private (contains-principal? (plist (list 20 principal)) (p principal))
  (get found (fold contains-fold-step plist {found: false, target: p}))
)

;; Private: buff21 a < buff21 b strictly (lex byte cmp; false if == or >)
(define-private (buff21-lt-fold-step (idx uint) (accum {res: (optional bool), a: (buff 21), b: (buff 21)}))
  (if (is-some (get res accum))
    accum
    (let (
        (byte-a (unwrap-panic (element-at? (get a accum) idx)))
        (byte-b (unwrap-panic (element-at? (get b accum) idx)))
      )
      (let (
        (new-res
          (if (< byte-a byte-b)
            (some true)
            (if (> byte-a byte-b)
              (some false)
              none
            )
          )
        )
      )
        (if (is-some new-res)
          {res: new-res, a: (get a accum), b: (get b accum)}
          accum
        )
      )
    )
  )
)

(define-private (buff21-lt? (a (buff 21)) (b (buff 21)))
  (match (get res (fold buff21-lt-fold-step
      (list 
        u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
        u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20
      )
      {res: none, a: a, b: b}
    )) some-val some-val false)
)

;; Private: participants strictly ascending sorted by buff21 lex (implies unique, no dups)
;; Fails if len>20, any consecutive not <, or len>=2 no pairs.
(define-private (sorted-fold-step (i uint) (accum {sorted: bool, plist: (list 20 principal), n: uint}))
  (let (
      (curr-sorted (get sorted accum))
      (curr-plist (get plist accum))
      (curr-n (get n accum))
    )
    (if (not curr-sorted)
        {sorted: false, plist: curr-plist, n: curr-n}
        (if (>= i (- curr-n u1))
            {sorted: true, plist: curr-plist, n: curr-n}
            (let (
                (curr (unwrap-panic (element-at? curr-plist i)))
                (next (unwrap-panic (element-at? curr-plist (+ i u1))))
                (curr-b (principal-buff21 curr))
                (next-b (principal-buff21 next))
              )
              {sorted: (and curr-sorted (buff21-lt? curr-b next-b)), plist: curr-plist, n: curr-n}
            )
        )
    )
  )
)

(define-private (is-sorted-principals? (plist (list 20 principal)))
  (let ((n (len plist)))
    (if (> n u20)
        false
        (if (<= n u1)
            true  ;; 0/1 trivial
            (get sorted (fold sorted-fold-step
                (list 
                  u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
                  u10 u11 u12 u13 u14 u15 u16 u17 u18 u19
                )
                {sorted: true, plist: plist, n: n}
            ))
        )
    )
  )
)

;; Chunk 2: EIP-712 hash helpers (sha256 adapted; LE uint serial via buff-from-uinteger pad-left0)
(define-constant DOMAIN_NAME_ASCII_STR "ERC-8001")
(define-constant DOMAIN_NAME_STR 0x4552432d38303031)
(define-constant DOMAIN_VERSION_ASCII_STR "1")
(define-constant DOMAIN_VERSION_STR 0x31)
(define-constant DOMAIN_NAME_HASH ;; sha256(DOMAIN_NAME_ASCII_STR)
  (sha256 DOMAIN_NAME_STR))
(define-constant DOMAIN_VERSION_HASH ;; sha256(DOMAIN_VERSION_ASCII_STR)
  (sha256 DOMAIN_VERSION_STR))

(define-constant AGENT_INTENT_TYPE_ASCII_STR "AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,bytes32 participantsHash)")
(define-constant AGENT_INTENT_TYPE_STR 0x4167656e74496e74656e742862797465733332207061796c6f6164486173682c75696e743634206578706972792c75696e743634206e6f6e63652c61646472657373206167656e7449642c6279746573333220636f6f7264696e6174696f6e547970652c75696e7432353620636f6f7264696e6174696f6e56616c75652c627974657332207061727469636970616e74734861736829)
(define-constant AGENT_INTENT_TYPEHASH ;; sha256(AGENT_INTENT_TYPE_ASCII_STR)
  (sha256 AGENT_INTENT_TYPE_STR))

(define-constant ACCEPTANCE_TYPE_ASCII_STR "AcceptanceAttestation(bytes32 intentHash,address participant,uint64 nonce,uint64 expiry,bytes32 conditionsHash)")
(define-constant ACCEPTANCE_TYPE_STR 0x416363657074616e63654174746573746174696f6e286279746573333220696e74656e74486173682c61646472657373207061727469636970616e742c75696e743634206e6f6e63652c75696e743634206578706972792c62797465733220636f6e646974696f6e734861736829)
(define-constant ACCEPTANCE_TYPEHASH ;; sha256(ACCEPTANCE_TYPE_ASCII_STR)
  (sha256 ACCEPTANCE_TYPE_STR))

(define-constant SIG_PREFIX (concat 0x19 0x01))

(define-constant PAD_ZERO_12 0x000000000000000000000000)


;; Private: uint -> buff32 Stacks-ABI encode (sha256(uint) canonical LE u128 bytes; match off-chain)
(define-private (buff32FromUint64 (n uint))
  (sha256 n)
)

(define-constant VERIFYING_CONTRACT_ASCII_STR "stacks-sip-erc8001-ref-v1")
(define-constant VERIFYING_CONTRACT_STR 0x737461636b732d7369702d657263383030312d7265662d7631)
(define-constant VERIFYING_CONTRACT_HASH ;; sha256(VERIFYING_CONTRACT_ASCII_STR)
  (sha256 VERIFYING_CONTRACT_STR))

;; Private: buff20 -> buff32 pad-right 0x00 (EIP address equiv)
(define-private (address-to-buff32 (p principal))
  (concat (principal-hash160 p) PAD_ZERO_12)
)

;; Private: domain separator (sha256(nameH32 + versionH32 + chainId32BE + verifyingFixed32))
(define-private (get-domain-separator)
  (let
    (
      (chain32 (buff32FromUint64 chain-id))
    )
    (sha256
      (concat DOMAIN_NAME_HASH
        (concat DOMAIN_VERSION_HASH
          (concat chain32 VERIFYING_CONTRACT_HASH)
        )
      )
    )
  )
)

;; Private: participants hash = sha256(concat(p1.hash160 || p2.hash160 || ...)) (EIP equiv)
(define-private (participants-to-hash (participants (list 20 principal)))
  (sha256
    (fold
      (lambda (h accum) (concat accum h))
      (map principal-hash160 participants)
      0x
    )
  )
)

;; Private: agent intent struct hash (sha256(typeH32 || payload32 || expiry64->32BE || nonce64->32BE || agent32 || type32 || value256->32BE || part32))
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
          (buff32FromUint64 expiry)
          (concat
            (buff32FromUint64 nonce)
            (concat
              (address-to-buff32 agent)
              (concat coord-type
                (concat
                  (buff32FromUint64 coord-value)
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

;; Private: acceptance struct hash (sha256(typeH32 || intent32 || part32 || nonce64->32BE || expiry64->32BE || cond32))
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
            (buff32FromUint64 accept-nonce)
            (concat
              (buff32FromUint64 accept-expiry)
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
      (now stacks-block-time)
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
        (map-insert intents {intent-hash: intent-hash}
          {
            agent: agent,
            payload-hash: payload-hash,
            expiry: expiry,
            nonce: nonce,
            coord-type: coord-type,
            coord-value: coord-value,
            participants: participants,
            status: PROPOSED,
            accept-count: u0
          }
        )
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

;; Public: participant accepts coordination (EIP acceptCoordination; tx-sender=participant, sig over acceptance-digest nonce=0)
(define-public (accept-coordination (intent-hash (buff 32)) (accept-expiry uint) (conditions (buff 32)) (sig (buff 65)))
  (let
    (
      (now stacks-block-time)
      (caller tx-sender)
      (intent-opt (map-get? intents {intent-hash: intent-hash}))
    )
    (asserts! (is-some intent-opt) ERR_NOT_FOUND)
    (let
      (
        (intent (unwrap! intent-opt ERR_NOT_FOUND))
      )
      (asserts! (> (get expiry intent) now) ERR_EXPIRED)
      (asserts! (is-eq (get status intent) PROPOSED) ERR_INVALID_STATE)
      (asserts! (contains-principal? (get participants intent) caller) ERR_NOT_PARTICIPANT)
      (asserts! (is-none (map-get? acceptances {intent-hash: intent-hash, participant: caller})) ERR_ALREADY_ACCEPTED)
      (asserts! (> accept-expiry now) ERR_ACCEPT_EXPIRED)
      (let
        (
          (accept-nonce u0)
          (digest (acceptance-digest intent-hash caller accept-nonce accept-expiry conditions))
          (pubkey-opt (secp256k1-recover? digest sig))
        )
        (asserts! (is-ok pubkey-opt) ERR_INVALID_SIG)
        (let
          (
            (pubkey (unwrap! pubkey-opt ERR_INVALID_SIG))
            (signer-opt (principal-of? pubkey))
          )
          (asserts! (is-ok signer-opt) ERR_INVALID_SIG)
          (asserts! (is-eq (unwrap! signer-opt ERR_INVALID_SIG) caller) ERR_INVALID_SIG)
          (map-insert acceptances {intent-hash: intent-hash, participant: caller}
            {accept-expiry: accept-expiry, conditions: conditions})
          (let
            (
              (old-count (get accept-count intent))
              (new-count (+ old-count u1))
              (total (len (get participants intent)))
              (new-status (if (>= new-count total) READY PROPOSED))
            )
            (map-set intents {intent-hash: intent-hash}
              (merge intent
                {accept-count: new-count, status: new-status}))
            (let ((acceptance-h (acceptance-struct-hash intent-hash caller accept-nonce accept-expiry conditions)))
              (print {
                event: "CoordinationAccepted",
                intent-hash: intent-hash,
                participant: caller,
                acceptance-hash: acceptance-h,
                accepted-count: new-count,
                required-count: total
              })
              (ok (>= new-count total))
            )
          )
        )
      )
    )
  )
)

;; Private: check all participants' acceptances are non-expired (assumes all accepted via count==len)
(define-private (fresh-fold-step (p principal) (accum {fresh: bool, now: uint, intent-hash: (buff 32)}))
  (if (not (get fresh accum))
    accum
    (let (
        (acc-opt (map-get? acceptances {intent-hash: (get intent-hash accum), participant: p}))
      )
      (match acc-opt
        acc {fresh: (and (get fresh accum) (>= (get accept-expiry acc) (get now accum))), 
             now: (get now accum), intent-hash: (get intent-hash accum)}
        none {fresh: false, now: (get now accum), intent-hash: (get intent-hash accum)}
      )
    )
  )
)

(define-private (all-acceptances-fresh? (intent-hash (buff 32)) (participants (list 20 principal)) (now uint))
  (get fresh (fold fresh-fold-step participants {fresh: true, now: now, intent-hash: intent-hash}))
)

;; Public: execute ready coordination (EIP executeCoordination; any caller, verify payload, state to Executed)
(define-public (execute-coordination (intent-hash (buff 32)) (payload (buff 1024)) (execution-data (buff 1024)))
  (let
    (
      (now stacks-block-time)
      (intent-opt (map-get? intents {intent-hash: intent-hash}))
    )
    (asserts! (is-some intent-opt) ERR_NOT_FOUND)
    (let
      (
        (intent (unwrap! intent-opt ERR_NOT_FOUND))
      )
      (asserts! (is-eq (get status intent) READY) ERR_INVALID_STATE)
      (asserts! (<= now (get expiry intent)) ERR_EXPIRED)
      (asserts! (all-acceptances-fresh? intent-hash (get participants intent) now) ERR_ACCEPT_EXPIRED)
      (asserts! (is-eq (sha256 payload) (get payload-hash intent)) ERR_PAYLOAD_HASH_MISMATCH)
      (let
        (
          (new-intent (merge intent {status: EXECUTED}))
        )
        (map-set intents {intent-hash: intent-hash} new-intent)
        (print {
          event: "CoordinationExecuted",
          intent-hash: intent-hash,
          executor: tx-sender,
          success: true,
          gasUsed: u0,
          result: 0x
        })
        (ok true 0x)
      )
    )
  )
)

;; Public: cancel coordination (EIP cancelCoordination; proposer pre-expiry or any post-expiry)
(define-public (cancel-coordination (intent-hash (buff 32)) (reason (string-ascii 34)))
  (let
    (
      (now stacks-block-time)
      (intent-opt (map-get? intents {intent-hash: intent-hash}))
    )
    (asserts! (is-some intent-opt) ERR_NOT_FOUND)
    (let
      (
        (intent (unwrap! intent-opt ERR_NOT_FOUND))
        (agent (get agent intent))
      )
      (asserts! (not (is-eq (get status intent) EXECUTED)) ERR_INVALID_STATE)
      (asserts! (not (is-eq (get status intent) CANCELLED)) ERR_INVALID_STATE)
      (asserts! (or (is-eq tx-sender agent) (> now (get expiry intent))) ERR_UNAUTHORIZED)
      (map-set intents {intent-hash: intent-hash} (merge intent {status: CANCELLED}))
      (print {
        event: "CoordinationCancelled",
        intent-hash: intent-hash,
        canceller: tx-sender,
        reason: reason,
        finalStatus: CANCELLED
      })
      (ok true)
    )
  )
)

;; Private: filter accepted participants (for status getter)
(define-private (is-accepted? (intent-hash (buff 32)) (p principal))
  (is-some (map-get? acceptances {intent-hash: intent-hash, participant: p}))
)

;; Private: filter step for accepted-by
(define-private (accepted-filter-step (p principal) (accum {accepted: (list 20 principal), intent-hash: (buff 32)}))
  (if (is-accepted? (get intent-hash accum) p)
    {accepted: (unwrap-panic (as-max-len? (append (get accepted accum) (list p)) u20)), 
     intent-hash: (get intent-hash accum)}
    accum
  )
)

;; Read-only: full coordination status (EIP getCoordinationStatus; auto-Expires if applicable)
(define-read-only (get-coordination-status (intent-hash (buff 32)))
  (let
    (
      (intent-opt (map-get? intents {intent-hash: intent-hash}))
      (now stacks-block-time)
    )
    (match intent-opt
      intent
      (let
        (
          (stored-status (get status intent))
          (expiry (get expiry intent))
          (effective-status
            (if (or (is-eq stored-status EXECUTED) (is-eq stored-status CANCELLED))
              stored-status
              (if (> now expiry) EXPIRED stored-status)
            )
          )
          (accepted-by
            (get accepted (fold accepted-filter-step (get participants intent) 
              {accepted: (unwrap-panic (as-max-len? (list) u20)), intent-hash: intent-hash}
            ))
          )
        )
        (ok
          {
            status: effective-status,
            agent: (get agent intent),
            participants: (get participants intent),
            accepted-by: accepted-by,
            expiry: expiry
          }
        )
      )
      (err ERR_NOT_FOUND)
    )
  )
)

;; Read-only: required acceptances count (EIP getRequiredAcceptances)
(define-read-only (get-required-acceptances (intent-hash (buff 32)))
  (match (map-get? intents {intent-hash: intent-hash})
    intent (ok (len (get participants intent)))
    (err ERR_NOT_FOUND)
  )
)

;; Read-only: agent's latest nonce (EIP getAgentNonce)
(define-read-only (get-agent-nonce (agent principal))
  (default-to u0 (map-get? agent-nonces {agent: agent}))
)

;; Read-only: EIP-712 constants for off-chain verification (ASCII str / buff / hash)
(define-read-only (get-eip712-constants)
  {
    domain: {
      name: {
        ascii: DOMAIN_NAME_ASCII_STR,
        buff: DOMAIN_NAME_STR,
        hash: DOMAIN_NAME_HASH
      },
      version: {
        ascii: DOMAIN_VERSION_ASCII_STR,
        buff: DOMAIN_VERSION_STR,
        hash: DOMAIN_VERSION_HASH
      }
    },
    verifying-contract: {
      ascii: VERIFYING_CONTRACT_ASCII_STR,
      buff: VERIFYING_CONTRACT_STR,
      hash: VERIFYING_CONTRACT_HASH
    },
    agent-intent-type: {
      ascii: AGENT_INTENT_TYPE_ASCII_STR,
      buff: AGENT_INTENT_TYPE_STR,
      hash: AGENT_INTENT_TYPEHASH
    },
    acceptance-type: {
      ascii: ACCEPTANCE_TYPE_ASCII_STR,
      buff: ACCEPTANCE_TYPE_STR,
      hash: ACCEPTANCE_TYPEHASH
    }
  }
)


