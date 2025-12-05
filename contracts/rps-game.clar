;; Rock-Paper-Scissors Game Extension for ERC-8001
;;
;; This contract demonstrates how to build a game on top of ERC-8001
;; coordination protocol. The game flow is:
;;
;; 1. Player A creates a game (proposes coordination)
;; 2. Both players commit their moves off-chain by signing acceptances
;; 3. Once both accept, the game can be executed with revealed moves
;; 4. Winner is determined and (optionally) stakes are transferred
;;
;; Move encoding: 0 = Rock, 1 = Paper, 2 = Scissors

;; =============================================================================
;; CONSTANTS
;; =============================================================================

(define-constant MOVE_ROCK u0)
(define-constant MOVE_PAPER u1)
(define-constant MOVE_SCISSORS u2)

(define-constant RESULT_TIE u0)
(define-constant RESULT_PLAYER_A_WINS u1)
(define-constant RESULT_PLAYER_B_WINS u2)

(define-constant ERR_INVALID_MOVE (err u200))
(define-constant ERR_GAME_NOT_FOUND (err u201))
(define-constant ERR_NOT_READY (err u202))
(define-constant ERR_INVALID_PLAYERS (err u203))

(define-constant COORDINATION_TYPE_RPS 0x5250532d47414d4500000000000000000000000000000000000000000000000000) ;; "RPS-GAME" padded to 32 bytes

;; =============================================================================
;; DATA MAPS
;; =============================================================================

;; Map intent-hash to game details
(define-map games
  { intent-hash: (buff 32) }
  {
    player-a: principal,
    player-b: principal,
    stake: uint,
    winner: (optional principal),
    result: (optional uint)
  }
)

;; =============================================================================
;; HELPER FUNCTIONS
;; =============================================================================

;; Determine winner: returns 0=tie, 1=a-wins, 2=b-wins
(define-private (determine-winner (move-a uint) (move-b uint))
  (if (is-eq move-a move-b)
    RESULT_TIE
    (if (is-eq move-a MOVE_ROCK)
      (if (is-eq move-b MOVE_SCISSORS) RESULT_PLAYER_A_WINS RESULT_PLAYER_B_WINS)
      (if (is-eq move-a MOVE_PAPER)
        (if (is-eq move-b MOVE_ROCK) RESULT_PLAYER_A_WINS RESULT_PLAYER_B_WINS)
        ;; move-a is SCISSORS
        (if (is-eq move-b MOVE_PAPER) RESULT_PLAYER_A_WINS RESULT_PLAYER_B_WINS)
      )
    )
  )
)

(define-private (is-valid-move (move uint))
  (or (is-eq move MOVE_ROCK)
      (or (is-eq move MOVE_PAPER)
          (is-eq move MOVE_SCISSORS)))
)

;; =============================================================================
;; PUBLIC FUNCTIONS
;; =============================================================================

;; Register a new game after coordination is proposed
;; Called by the game creator after propose-coordination succeeds
(define-public (register-game
    (intent-hash (buff 32))
    (player-a principal)
    (player-b principal)
    (stake uint))
  (begin
    ;; Verify game doesn't already exist
    (asserts! (is-none (map-get? games { intent-hash: intent-hash }))
              (err u210))

    ;; Store game info
    (map-set games { intent-hash: intent-hash }
      {
        player-a: player-a,
        player-b: player-b,
        stake: stake,
        winner: none,
        result: none
      }
    )

    (print {
      event: "rps-game-registered",
      intent-hash: intent-hash,
      player-a: player-a,
      player-b: player-b,
      stake: stake
    })

    (ok true)
  )
)

;; Reveal moves and determine winner
;; This is called after execute-coordination succeeds
;; The payload format is: (move-a: uint, move-b: uint, salt: (buff 32))
(define-public (reveal-winner
    (intent-hash (buff 32))
    (move-a uint)
    (move-b uint))
  (let (
    (game (unwrap! (map-get? games { intent-hash: intent-hash }) ERR_GAME_NOT_FOUND))
  )
    ;; Validate moves
    (asserts! (is-valid-move move-a) ERR_INVALID_MOVE)
    (asserts! (is-valid-move move-b) ERR_INVALID_MOVE)

    (let (
      (result (determine-winner move-a move-b))
      (winner (if (is-eq result RESULT_PLAYER_A_WINS)
                (some (get player-a game))
                (if (is-eq result RESULT_PLAYER_B_WINS)
                  (some (get player-b game))
                  none)))
    )
      ;; Update game with result
      (map-set games { intent-hash: intent-hash }
        (merge game {
          winner: winner,
          result: (some result)
        })
      )

      (print {
        event: "rps-game-resolved",
        intent-hash: intent-hash,
        move-a: move-a,
        move-b: move-b,
        result: result,
        winner: winner
      })

      ;; In a real implementation, transfer stake to winner here
      ;; (try! (stx-transfer? stake (get player-b game) (unwrap-panic winner)))

      (ok { result: result, winner: winner })
    )
  )
)

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

(define-read-only (get-game (intent-hash (buff 32)))
  (map-get? games { intent-hash: intent-hash })
)

(define-read-only (get-move-name (move uint))
  (if (is-eq move MOVE_ROCK)
    "Rock"
    (if (is-eq move MOVE_PAPER)
      "Paper"
      (if (is-eq move MOVE_SCISSORS)
        "Scissors"
        "Invalid"
      )
    )
  )
)

;; =============================================================================
;; USAGE EXAMPLE (in comments)
;; =============================================================================
;;
;; // TypeScript client code for playing RPS:
;;
;; async function playRPS(playerA: string, playerB: string, stake: number) {
;;   // 1. Both players choose moves off-chain
;;   const moveA = 0; // Rock
;;   const moveB = 1; // Paper
;;   const salt = randomBytes(32);
;;
;;   // 2. Create payload hash (commitment)
;;   const payload = encodePayload(moveA, moveB, salt);
;;   const payloadHash = sha256(payload);
;;
;;   // 3. Player A proposes coordination
;;   const participants = sortPrincipals([playerA, playerB]);
;;   const intentHash = await contract.proposeCoordination(
;;     payloadHash,
;;     Math.floor(Date.now()/1000) + 3600, // 1 hour expiry (Clarity 4)
;;     nonce,
;;     COORDINATION_TYPE_RPS,
;;     stake,
;;     participants
;;   );
;;
;;   // 4. Register the game
;;   await rpsContract.registerGame(intentHash, playerA, playerB, stake);
;;
;;   // 5. Both players sign acceptances
;;   const acceptanceA = await signAcceptance(intentHash, playerA, expiry, conditions);
;;   const acceptanceB = await signAcceptance(intentHash, playerB, expiry, conditions);
;;
;;   // 6. Submit acceptances to contract
;;   await contract.acceptCoordination(intentHash, expiry, conditions, acceptanceA.signature);
;;   await contract.acceptCoordination(intentHash, expiry, conditions, acceptanceB.signature);
;;
;;   // 7. Execute coordination with revealed payload
;;   await contract.executeCoordination(intentHash, payload, executionData);
;;
;;   // 8. Reveal winner
;;   const result = await rpsContract.revealWinner(intentHash, moveA, moveB);
;;   console.log(`Winner: ${result.winner}`);
;; }
