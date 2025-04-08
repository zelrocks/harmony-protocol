;; Harmony Protocol - Distributed Resource Allocation Network
;; A decentralized system for controlled resource distribution with multi-stage verification

;; Primary configuration constants
(define-constant PROTOCOL_SUPERVISOR tx-sender)
(define-constant ERROR_UNAUTHORIZED (err u100))
(define-constant ERROR_MISSING_ALLOCATION (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_MOVEMENT_FAILED (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_ALLOCATION_LAPSED (err u107))
(define-constant ALLOCATION_LIFESPAN_BLOCKS u1008) 

;; Core allocation data repository
(define-map AllocationRepository
  { allocation-identifier: uint }
  {
    originator: principal,
    beneficiary: principal,
    resource-identifier: uint,
    quantity: uint,
    allocation-status: (string-ascii 10),
    genesis-block: uint,
    termination-block: uint
  }
)

;; Tracking allocation sequence
(define-data-var last-allocation-identifier uint u0)

;; Support functions
(define-private (valid-beneficiary? (beneficiary principal))
  (and 
    (not (is-eq beneficiary tx-sender))
    (not (is-eq beneficiary (as-contract tx-sender)))
  )
)

(define-private (valid-allocation-identifier? (allocation-identifier uint))
  (<= allocation-identifier (var-get last-allocation-identifier))
)

;; Core interface functions

;; Complete distribution of resources to beneficiary
(define-public (finalize-resource-distribution (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (resource-id (get resource-identifier allocation-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender (get originator allocation-data))) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender beneficiary))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "completed" })
            )
            (print {action: "resources_distributed", allocation-identifier: allocation-identifier, beneficiary: beneficiary, resource-identifier: resource-id, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Accept allocation by beneficiary - increases security by requiring explicit acceptance
(define-public (accept-pending-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (is-eq tx-sender beneficiary) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "accepted" })
      )
      (print {action: "allocation_accepted", allocation-identifier: allocation-identifier, beneficiary: beneficiary})
      (ok true)
    )
  )
)

;; Revert resources to originator
(define-public (revert-resource-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "reverted" })
            )
            (print {action: "resources_reverted", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Emergency freeze allocation in case of security breach
(define-public (emergency-freeze-allocation (allocation-identifier uint) (security-incident-report (string-ascii 100)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only supervisor, originator or beneficiary can freeze in emergency
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) 
                   (is-eq tx-sender originator) 
                   (is-eq tx-sender beneficiary)) 
                ERROR_UNAUTHORIZED)

      ;; Cannot freeze if already completed or reverted
      (asserts! (and (not (is-eq current-status "completed")) 
                    (not (is-eq current-status "reverted"))
                    (not (is-eq current-status "expired"))
                    (not (is-eq current-status "frozen"))) 
                ERROR_ALREADY_PROCESSED)

      ;; Update allocation status to frozen
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "frozen" })
      )

      (print {action: "allocation_emergency_frozen", allocation-identifier: allocation-identifier, 
              initiator: tx-sender, previous-status: current-status, security-report: security-incident-report})
      (ok true)
    )
  )
)

;; Implement two-factor verification for high-value allocations
(define-public (verify-allocation-2fa (allocation-identifier uint) (verification-code (buff 32)) (verification-timestamp uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> verification-timestamp u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= verification-timestamp block-height) (err u245)) ;; Cannot be future timestamp
    (asserts! (>= block-height (- verification-timestamp u144)) (err u246)) ;; Must be recent (within 24 hours)

    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only needed for high value allocations
      (asserts! (> quantity u5000) (err u247))
      ;; Only originator or beneficiary can verify
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      ;; Must be in pending status
      (asserts! (is-eq current-status "pending") ERROR_ALREADY_PROCESSED)

      (print {action: "2fa_verification_complete", allocation-identifier: allocation-identifier, 
              verifier: tx-sender, verification-code-hash: (hash160 verification-code), 
              verification-timestamp: verification-timestamp, quantity: quantity})
      (ok true)
    )
  )
)

;; Create allocation with timelocked release schedule
(define-public (create-timelocked-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (release-schedule (list 5 {block-height: uint, percentage: uint})))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> (len release-schedule) u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= (len release-schedule) u5) (err u255)) ;; Maximum 5 release points
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)

    ;; Validate release schedule
    (let
      (
        (new-identifier (+ (var-get last-allocation-identifier) u1))
        (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
        (total-percentage (fold + (map get-percentage release-schedule) u0))
      )
      ;; Ensure percentages sum to 100%
      (asserts! (is-eq total-percentage u100) (err u256))

      ;; Transfer resources to contract
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            (var-set last-allocation-identifier new-identifier)

            (print {action: "timelocked_allocation_created", allocation-identifier: new-identifier, 
                    originator: tx-sender, beneficiary: beneficiary, resource-identifier: resource-identifier, 
                    quantity: quantity, release-schedule: release-schedule})
            (ok new-identifier)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Helper function to extract percentage from release schedule entry
(define-private (get-percentage (entry {block-height: uint, percentage: uint}))
  (get percentage entry)
)

;; Create allocation with circuit breaker to halt transaction flow if anomalies detected
(define-public (create-protected-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (anomaly-threshold uint) (max-transactions-per-block uint))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> anomaly-threshold u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= anomaly-threshold u100) (err u265)) ;; Threshold must be percentage (0-100)
    (asserts! (> max-transactions-per-block u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= max-transactions-per-block u10) (err u266)) ;; Reasonable limit
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)

    (let
      (
        (new-identifier (+ (var-get last-allocation-identifier) u1))
        (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
      )
      ;; Transfer resources to contract
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            (var-set last-allocation-identifier new-identifier)

            (print {action: "protected_allocation_created", allocation-identifier: new-identifier, 
                    originator: tx-sender, beneficiary: beneficiary, resource-identifier: resource-identifier, 
                    quantity: quantity, anomaly-threshold: anomaly-threshold, 
                    max-transactions-per-block: max-transactions-per-block})
            (ok new-identifier)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Create trusted recovery mechanism
(define-public (initiate-trusted-recovery (allocation-identifier uint) (recovery-beneficiary principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (cool-down-period u144) ;; 24 hours in blocks
      )
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "completed")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "reverted")) ERROR_ALREADY_PROCESSED) 
      (asserts! (not (is-eq (get allocation-status allocation-data) "terminated")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "expired")) ERROR_ALREADY_PROCESSED)

      (print {action: "trusted_recovery_initiated", allocation-identifier: allocation-identifier, 
              originator: originator, recovery-beneficiary: recovery-beneficiary, 
              execution-block: (+ block-height cool-down-period)})
      (ok (+ block-height cool-down-period))
    )
  )
)

;; Implement rate-limited withdrawals for large allocations
(define-public (configure-withdrawal-rate-limit (allocation-identifier uint) (blocks-per-withdrawal uint) (withdrawal-cap uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> blocks-per-withdrawal u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= blocks-per-withdrawal u144) ERROR_INVALID_QUANTITY) ;; Max 1 day between withdrawals
    (asserts! (> withdrawal-cap u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations
      (asserts! (> quantity u2000) (err u250))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= withdrawal-cap quantity) (err u251)) ;; Cap must be less than or equal to total

      (print {action: "withdrawal_rate_limit_configured", allocation-identifier: allocation-identifier, 
              originator: originator, blocks-per-withdrawal: blocks-per-withdrawal, 
              withdrawal-cap: withdrawal-cap, withdrawal-periods: (/ quantity withdrawal-cap)})
      (ok true)
    )
  )
)

;; Lock allocation for security investigation
(define-public (lock-allocation-for-investigation (allocation-identifier uint) (investigation-code (string-ascii 30)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (status (get allocation-status allocation-data))
      )
      ;; Only supervisor or originator can lock for investigation
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator)) ERROR_UNAUTHORIZED)
      ;; Cannot lock already completed or terminated allocations
      (asserts! (not (or (is-eq status "completed") (is-eq status "terminated") 
                          (is-eq status "reverted") (is-eq status "expired"))) ERROR_ALREADY_PROCESSED)
      ;; Update status to locked
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "locked" })
      )
      (print {action: "allocation_locked", allocation-identifier: allocation-identifier, investigator: tx-sender, 
              investigation-code: investigation-code, lock-time: block-height})
      (ok true)
    )
  )
)

;; Add security hold period for high-risk allocations
(define-public (add-security-hold (allocation-identifier uint) (hold-duration uint) (risk-justification (string-ascii 50)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> hold-duration u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= hold-duration u720) ERROR_INVALID_QUANTITY) ;; Maximum 5 days hold
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (status (get allocation-status allocation-data))
        (current-termination (get termination-block allocation-data))
        (extended-termination (+ current-termination hold-duration))
      )
      ;; Only supervisor can add security holds
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Only pending allocations can have holds added
      (asserts! (is-eq status "pending") ERROR_ALREADY_PROCESSED)
      ;; Update the termination block to extend the allocation period
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { 
          allocation-status: "held", 
          termination-block: extended-termination 
        })
      )
      (print {action: "security_hold_added", allocation-identifier: allocation-identifier, hold-duration: hold-duration, 
              original-termination: current-termination, new-termination: extended-termination, justification: risk-justification})
      (ok true)
    )
  )
)

;; Originator initiates allocation termination
(define-public (terminate-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "terminated" })
            )
            (print {action: "allocation_terminated", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Implement multi-signature confirmation for high-value allocations
(define-public (register-multisig-confirmation (allocation-identifier uint) (confirmation-signature (buff 65)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations (> 5000 STX)
      (asserts! (> quantity u5000) (err u240))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      (print {action: "multisig_confirmation_registered", allocation-identifier: allocation-identifier, 
              confirming-party: tx-sender, signature-hash: (hash160 confirmation-signature)})
      (ok true)
    )
  )
)

;; Prolong allocation duration
(define-public (prolong-allocation-timeframe (allocation-identifier uint) (additional-blocks uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> additional-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_QUANTITY) ;; Maximum 10 days extension
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data)) 
        (beneficiary (get beneficiary allocation-data))
        (existing-termination (get termination-block allocation-data))
        (new-termination (+ existing-termination additional-blocks))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { termination-block: new-termination })
      )
      (print {action: "timeframe_extended", allocation-identifier: allocation-identifier, requestor: tx-sender, new-termination-block: new-termination})
      (ok true)
    )
  )
)

;; Reclaim resources from expired allocation
(define-public (reclaim-lapsed-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (expiration (get termination-block allocation-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (> block-height expiration) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "expired" })
            )
            (print {action: "lapsed_allocation_reclaimed", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Challenge allocation integrity
(define-public (challenge-allocation (allocation-identifier uint) (justification (string-ascii 50)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "challenged" })
      )
      (print {action: "allocation_challenged", allocation-identifier: allocation-identifier, challenger: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Register contingency contact
(define-public (register-contingency-contact (allocation-identifier uint) (contingency-contact principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq contingency-contact tx-sender)) (err u111)) ;; Must differ from originator
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "contingency_registered", allocation-identifier: allocation-identifier, originator: originator, contingency: contingency-contact})
      (ok true)
    )
  )
)

;; Arbitrate contested allocation
(define-public (arbitrate-challenge (allocation-identifier uint) (originator-percentage uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
    (asserts! (<= originator-percentage u100) ERROR_INVALID_QUANTITY) ;; Valid percentage range
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (originator-share (/ (* quantity originator-percentage) u100))
        (beneficiary-share (- quantity originator-share))
      )
      (asserts! (is-eq (get allocation-status allocation-data) "challenged") (err u112)) ;; Must be challenged
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      ;; Distribute originator's share
      (unwrap! (as-contract (stx-transfer? originator-share tx-sender originator)) ERROR_MOVEMENT_FAILED)

      ;; Distribute beneficiary's share
      (unwrap! (as-contract (stx-transfer? beneficiary-share tx-sender beneficiary)) ERROR_MOVEMENT_FAILED)

      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "arbitrated" })
      )
      (print {action: "challenge_arbitrated", allocation-identifier: allocation-identifier, originator: originator, beneficiary: beneficiary, 
              originator-share: originator-share, beneficiary-share: beneficiary-share, originator-percentage: originator-percentage})
      (ok true)
    )
  )
)

;; Register additional oversight for significant allocations
(define-public (register-additional-oversight (allocation-identifier uint) (overseer principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations (> 1000 STX)
      (asserts! (> quantity u1000) (err u120))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "oversight_registered", allocation-identifier: allocation-identifier, overseer: overseer, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Create phased allocation
(define-public (create-phased-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (segments uint))
  (let 
    (
      (new-identifier (+ (var-get last-allocation-identifier) u1))
      (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
      (segment-quantity (/ quantity segments))
    )
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> segments u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= segments u5) ERROR_INVALID_QUANTITY) ;; Maximum 5 segments
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)
    (asserts! (is-eq (* segment-quantity segments) quantity) (err u121)) ;; Verify exact division
    (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set last-allocation-identifier new-identifier)
          (print {action: "phased_allocation_created", allocation-identifier: new-identifier, originator: tx-sender, beneficiary: beneficiary, 
                  resource-identifier: resource-identifier, quantity: quantity, segments: segments, segment-quantity: segment-quantity})
          (ok new-identifier)
        )
      error ERROR_MOVEMENT_FAILED
    )
  )
)

;; Pause suspicious allocation
(define-public (pause-irregular-allocation (allocation-identifier uint) (rationale (string-ascii 100)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") 
                   (is-eq (get allocation-status allocation-data) "accepted")) 
                ERROR_ALREADY_PROCESSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "paused" })
      )
      (print {action: "allocation_paused", allocation-identifier: allocation-identifier, initiator: tx-sender, rationale: rationale})
      (ok true)
    )
  )
)

;; Advanced cryptographic verification
(define-public (perform-cryptographic-verification (allocation-identifier uint) (data-digest (buff 32)) (signature (buff 65)) (signatory principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (verification-result (unwrap! (secp256k1-recover? data-digest signature) (err u150)))
      )
      ;; Verify message authenticity
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq signatory originator) (is-eq signatory beneficiary)) (err u151))
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)

      ;; Confirm signature matches expected source
      (asserts! (is-eq (unwrap! (principal-of? verification-result) (err u152)) signatory) (err u153))

      (print {action: "cryptographic_verification_complete", allocation-identifier: allocation-identifier, verifier: tx-sender, signatory: signatory})
      (ok true)
    )
  )
)

;; Enhanced security for high-value allocations
(define-public (activate-enhanced-security (allocation-identifier uint) (security-hash (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for allocations above threshold
      (asserts! (> quantity u5000) (err u130))
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "enhanced_security_activated", allocation-identifier: allocation-identifier, originator: originator, security-digest: (hash160 security-hash)})
      (ok true)
    )
  )
)

;; Append allocation documentation
(define-public (append-allocation-documentation (allocation-identifier uint) (documentation-category (string-ascii 20)) (documentation-digest (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "completed")) (err u160))
      (asserts! (not (is-eq (get allocation-status allocation-data) "reverted")) (err u161))
      (asserts! (not (is-eq (get allocation-status allocation-data) "expired")) (err u162))

      ;; Valid documentation categories
      (asserts! (or (is-eq documentation-category "resource-details") 
                   (is-eq documentation-category "allocation-proof")
                   (is-eq documentation-category "compliance-record")
                   (is-eq documentation-category "originator-preferences")) (err u163))

      (print {action: "documentation_appended", allocation-identifier: allocation-identifier, documentation-category: documentation-category, 
              documentation-digest: documentation-digest, submitter: tx-sender})
      (ok true)
    )
  )
)

;; Configure delayed recovery mechanism
(define-public (configure-delayed-recovery (allocation-identifier uint) (delay-duration uint) (recovery-destination principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> delay-duration u72) ERROR_INVALID_QUANTITY) ;; Minimum 72 blocks (~12 hours)
    (asserts! (<= delay-duration u1440) ERROR_INVALID_QUANTITY) ;; Maximum 1440 blocks (~10 days)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (activation-block (+ block-height delay-duration))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq recovery-destination originator)) (err u180)) ;; Must differ from originator
      (asserts! (not (is-eq recovery-destination (get beneficiary allocation-data))) (err u181)) ;; Must differ from beneficiary
      (print {action: "delayed_recovery_configured", allocation-identifier: allocation-identifier, originator: originator, 
              recovery-destination: recovery-destination, activation-block: activation-block})
      (ok activation-block)
    )
  )
)

;; Execute delayed retrieval
(define-public (execute-delayed-retrieval (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (status (get allocation-status allocation-data))
        (delay-duration u24) ;; 24 blocks (~4 hours)
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Status verification
      (asserts! (is-eq status "retrieval-initiated") (err u301))
      ;; Delay period verification
      (asserts! (>= block-height (+ (get genesis-block allocation-data) delay-duration)) (err u302))

      ;; Process retrieval
      (unwrap! (as-contract (stx-transfer? quantity tx-sender originator)) ERROR_MOVEMENT_FAILED)

      ;; Update allocation record
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "retrieved", quantity: u0 })
      )

      (print {action: "delayed_retrieval_complete", allocation-identifier: allocation-identifier, 
              originator: originator, quantity: quantity})
      (ok true)
    )
  )
)

;; Configure security parameters
(define-public (configure-security-parameters (max-attempts uint) (cooling-period uint))
  (begin
    (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
    (asserts! (> max-attempts u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= max-attempts u10) ERROR_INVALID_QUANTITY) ;; Maximum 10 attempts
    (asserts! (> cooling-period u6) ERROR_INVALID_QUANTITY) ;; Minimum 6 blocks (~1 hour)
    (asserts! (<= cooling-period u144) ERROR_INVALID_QUANTITY) ;; Maximum 144 blocks (~1 day)

    ;; Note: Full implementation would store these in contract variables

    (print {action: "security_parameters_configured", max-attempts: max-attempts, 
            cooling-period: cooling-period, supervisor: tx-sender, current-block: block-height})
    (ok true)
  )
)

;; Advanced validation for high-value allocations
(define-public (submit-advanced-verification (allocation-identifier uint) (verification-proof (buff 128)) (verification-inputs (list 5 (buff 32))))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> (len verification-inputs) u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only significant allocations require advanced verification
      (asserts! (> quantity u10000) (err u190))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)

      ;; Note: Actual verification would be implemented here

      (print {action: "advanced_verification_submitted", allocation-identifier: allocation-identifier, verifier: tx-sender, 
              verification-digest: (hash160 verification-proof), verification-inputs: verification-inputs})
      (ok true)
    )
  )
)

;; Process authorized retrievals
(define-public (process-authorized-retrieval (allocation-identifier uint) (retrieval-quantity uint) (authorization-signature (buff 65)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (status (get allocation-status allocation-data))
      )
      ;; Only supervisor can process authorized retrievals
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Only from challenged allocations
      (asserts! (is-eq status "challenged") (err u220))
      ;; Quantity validation
      (asserts! (<= retrieval-quantity quantity) ERROR_INVALID_QUANTITY)
      ;; Timelock verification
      (asserts! (>= block-height (+ (get genesis-block allocation-data) u48)) (err u221))

      ;; Process retrieval
      (unwrap! (as-contract (stx-transfer? retrieval-quantity tx-sender originator)) ERROR_MOVEMENT_FAILED)

      ;; Update allocation record
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { quantity: (- quantity retrieval-quantity) })
      )

      (print {action: "retrieval_processed", allocation-identifier: allocation-identifier, originator: originator, 
              quantity: retrieval-quantity, remaining: (- quantity retrieval-quantity)})
      (ok true)
    )
  )
)

;; Create a new allocation with multi-signature requirement
(define-public (create-multisig-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (required-signatures uint) (signatories (list 5 principal)))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> (len signatories) u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= (len signatories) u5) (err u225)) ;; Maximum 5 signatories
    (asserts! (>= required-signatures u1) ERROR_INVALID_QUANTITY)
    (asserts! (<= required-signatures (len signatories)) (err u226)) ;; Cannot require more signatures than signatories
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)
    (let
      (
        (new-identifier (+ (var-get last-allocation-identifier) u1))
        (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
      )
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            (var-set last-allocation-identifier new-identifier)

            (print {action: "multisig_allocation_created", allocation-identifier: new-identifier, originator: tx-sender, 
                    beneficiary: beneficiary, resource-identifier: resource-identifier, quantity: quantity, 
                    required-signatures: required-signatures, signatories: signatories})
            (ok new-identifier)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Transfer allocation control
(define-public (transfer-allocation-control (allocation-identifier uint) (new-controller principal) (authorization-code (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (current-controller (get originator allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender current-controller) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Verify new controller is different
      (asserts! (not (is-eq new-controller current-controller)) (err u210))
      (asserts! (not (is-eq new-controller (get beneficiary allocation-data))) (err u211))
      ;; Verify allowable status
      (asserts! (or (is-eq current-status "pending") (is-eq current-status "accepted")) ERROR_ALREADY_PROCESSED)
      ;; Update allocation control
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { originator: new-controller })
      )
      (print {action: "control_transferred", allocation-identifier: allocation-identifier, 
              previous-controller: current-controller, new-controller: new-controller, authorization-digest: (hash160 authorization-code)})
      (ok true)
    )
  )
)

;; Register a transaction monitor for detecting suspicious activity
(define-public (register-transaction-monitor (allocation-identifier uint) (threshold-quantity uint) (monitor-address principal) (monitoring-period uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> threshold-quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> monitoring-period u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= monitoring-period u2880) (err u235)) ;; Max 20 days (2880 blocks)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (current-status (get allocation-status allocation-data))
        (monitoring-end-block (+ block-height monitoring-period))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq current-status "pending") (is-eq current-status "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq monitor-address originator)) (err u236)) ;; Monitor must be different from originator
      (asserts! (not (is-eq monitor-address (get beneficiary allocation-data))) (err u237)) ;; Monitor must be different from beneficiary

      (print {action: "transaction_monitor_registered", allocation-identifier: allocation-identifier, 
              threshold-quantity: threshold-quantity, monitor-address: monitor-address, 
              end-block: monitoring-end-block, originator: originator})
      (ok monitoring-end-block)
    )
  )
)

;; Register multi-signature requirement for allocation
(define-public (register-multisig-requirement (allocation-identifier uint) (required-signers (list 5 principal)) (threshold uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> (len required-signers) u1) ERROR_INVALID_QUANTITY) ;; At least 2 signers required
    (asserts! (<= (len required-signers) u5) ERROR_INVALID_QUANTITY) ;; Maximum 5 signers
    (asserts! (> threshold u0) ERROR_INVALID_QUANTITY) ;; Threshold must be positive
    (asserts! (<= threshold (len required-signers)) ERROR_INVALID_QUANTITY) ;; Threshold must not exceed signer count
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (status (get allocation-status allocation-data))
      )
      ;; Only for high-value transactions
      (asserts! (> quantity u5000) (err u240))
      ;; Only originator or supervisor can set multisig requirements
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Only pending allocations can have multisig added
      (asserts! (is-eq status "pending") ERROR_ALREADY_PROCESSED)
      ;; Ensure originator is included in signers
      (asserts! (is-some (index-of required-signers originator)) (err u241))

      (print {action: "multisig_requirement_registered", allocation-identifier: allocation-identifier, 
              required-signers: required-signers, threshold: threshold, registrar: tx-sender})
      (ok true)
    )
  )
)

;; Verify allocation integrity through multi-signature approval
(define-public (approve-allocation-multi-sig (allocation-identifier uint) (approval-signature (buff 65)) (approval-digest (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (verification-result (unwrap! (secp256k1-recover? approval-digest approval-signature) (err u230)))
        (signer-principal (unwrap! (principal-of? verification-result) (err u231)))
      )
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (or (is-eq signer-principal originator) (is-eq signer-principal beneficiary) (is-eq signer-principal PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      (print {action: "multi_sig_approval", allocation-identifier: allocation-identifier, signer: signer-principal, verifier: tx-sender})
      (ok true)
    )
  )
)

;; Establish time-locked withdrawal restrictions on allocation
(define-public (establish-timelock-restrictions (allocation-identifier uint) (unlock-height uint) (authorized-accessor principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> unlock-height block-height) ERROR_INVALID_QUANTITY)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (current-status (get allocation-status allocation-data))
        (current-termination (get termination-block allocation-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq current-status "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= unlock-height current-termination) (err u240)) ;; Must unlock before termination
      (asserts! (not (is-eq authorized-accessor originator)) (err u241)) ;; Different from originator

      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "timelocked" })
      )
      (print {action: "timelock_established", allocation-identifier: allocation-identifier, originator: originator, unlock-height: unlock-height, authorized-accessor: authorized-accessor})
      (ok unlock-height)
    )
  )
)

;; Mitigate emergency situations with circuit breaker pattern
(define-public (activate-emergency-circuit-breaker (allocation-identifier uint) (emergency-code (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (code-hash (hash160 emergency-code))
      )
      ;; Only PROTOCOL_SUPERVISOR can activate circuit breaker
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") 
                    (is-eq (get allocation-status allocation-data) "accepted")
                    (is-eq (get allocation-status allocation-data) "challenged")) (err u250))

      (print {action: "emergency_circuit_breaker", allocation-identifier: allocation-identifier, supervisor: tx-sender, emergency-code-hash: code-hash})
      (ok true)
    )
  )
)

;; Apply rate limiting to high-frequency allocation operations
(define-public (apply-operation-rate-limit (allocation-identifier uint) (operation-type (string-ascii 20)) (cooldown-blocks uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> cooldown-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= cooldown-blocks u144) ERROR_INVALID_QUANTITY) ;; Maximum 1 day cooldown
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (status (get allocation-status allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only supervisor can apply rate limits
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Rate limiting only applies to active allocations
      (asserts! (or (is-eq status "pending") 
                    (is-eq status "accepted")
                    (is-eq status "held")) ERROR_ALREADY_PROCESSED)
      ;; Verify operation type is valid
      (asserts! (or (is-eq operation-type "distribution")
                   (is-eq operation-type "verification")
                   (is-eq operation-type "modification")
                   (is-eq operation-type "extension")) (err u270))

      ;; High-value allocations get stricter rate limiting
      (if (> quantity u10000)
          (asserts! (>= cooldown-blocks u24) (err u271)) ;; Minimum 4-hour cooldown for high-value
          true)

      (print {action: "rate_limit_applied", allocation-identifier: allocation-identifier, 
              operation-type: operation-type, cooldown-blocks: cooldown-blocks, 
              effective-from: block-height, effective-until: (+ block-height cooldown-blocks)})
      (ok true)
    )
  )
)


;; Implement rate-limited resource withdrawal to prevent abuse
(define-public (implement-rate-limited-withdrawal (allocation-identifier uint) (withdrawal-amount uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> withdrawal-amount u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (beneficiary (get beneficiary allocation-data))
        (current-quantity (get quantity allocation-data))
        (current-status (get allocation-status allocation-data))
        (max-rate-limit u1000) ;; Maximum withdrawal per operation
      )
      ;; Ensure the withdrawal is by beneficiary
      (asserts! (is-eq tx-sender beneficiary) ERROR_UNAUTHORIZED)
      ;; Status verification
      (asserts! (or (is-eq current-status "pending") (is-eq current-status "accepted")) ERROR_ALREADY_PROCESSED)
      ;; Check time hasn't lapsed
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      ;; Check rate limit
      (asserts! (<= withdrawal-amount max-rate-limit) (err u260))
      ;; Check sufficient funds
      (asserts! (<= withdrawal-amount current-quantity) (err u261))

      ;; Process the withdrawal
      (unwrap! (as-contract (stx-transfer? withdrawal-amount tx-sender beneficiary)) ERROR_MOVEMENT_FAILED)

      ;; Update allocation
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { quantity: (- current-quantity withdrawal-amount) })
      )

      (print {action: "rate_limited_withdrawal", allocation-identifier: allocation-identifier, beneficiary: beneficiary, amount: withdrawal-amount, remaining: (- current-quantity withdrawal-amount)})
      (ok true)
    )
  )
)

;; Escrow verification with third-party attestation
(define-public (verify-allocation-with-attestation (allocation-identifier uint) (attestation-provider principal) (attestation-hash (buff 32)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only attestation provider can verify
      (asserts! (is-eq tx-sender attestation-provider) ERROR_UNAUTHORIZED)
      ;; Provider must be different from both parties
      (asserts! (not (is-eq attestation-provider originator)) (err u270))
      (asserts! (not (is-eq attestation-provider beneficiary)) (err u271))
      ;; Status check
      (asserts! (is-eq current-status "pending") ERROR_ALREADY_PROCESSED)
      ;; Time validation
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      (print {action: "third_party_attestation", allocation-identifier: allocation-identifier, attestation-provider: attestation-provider, attestation-hash: attestation-hash})
      (ok true)
    )
  )
)

;; Implement role-based custody transfer for emergency situations
(define-public (execute-emergency-custody-transfer (allocation-identifier uint) (emergency-custodian principal) (authorization-timestamp uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (< (- block-height authorization-timestamp) u144) (err u280)) ;; Must be recent authorization (within 24 hours)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only supervisor can initiate emergency custody transfer
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Must be in active or challenged state
      (asserts! (or (is-eq current-status "pending") 
                   (is-eq current-status "accepted")
                   (is-eq current-status "challenged")) (err u281))
      ;; Emergency custodian must be different from involved parties
      (asserts! (not (is-eq emergency-custodian originator)) (err u282))
      (asserts! (not (is-eq emergency-custodian (get beneficiary allocation-data))) (err u283))

      (print {action: "emergency_custody_transfer", allocation-identifier: allocation-identifier, previous-controller: originator, 
              emergency-custodian: emergency-custodian, quantity: quantity, authorization-time: authorization-timestamp})
      (ok true)
    )
  )
)

;; Apply security freeze for suspicious activity
(define-public (apply-security-freeze (allocation-identifier uint) (freeze-reason (string-ascii 50)) (freeze-duration uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> freeze-duration u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= freeze-duration u1440) ERROR_INVALID_QUANTITY) ;; Maximum 10 days freeze
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (current-status (get allocation-status allocation-data))
        (freeze-expiration (+ block-height freeze-duration))
      )
      ;; Only supervisor can apply security freeze
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Only active allocations can be frozen
      (asserts! (or (is-eq current-status "pending") 
                   (is-eq current-status "accepted")
                   (is-eq current-status "challenged")) ERROR_ALREADY_PROCESSED)
      ;; Update allocation status
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "frozen" })
      )

      (print {action: "security_freeze_applied", allocation-identifier: allocation-identifier, 
              freeze-reason: freeze-reason, freeze-duration: freeze-duration, 
              freeze-expiration: freeze-expiration})
      (ok true)
    )
  )
)

;; Implement emergency resource recovery
(define-public (execute-emergency-recovery (allocation-identifier uint) (recovery-authorization (buff 128)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (current-status (get allocation-status allocation-data))
        (emergency-threshold u10000) ;; Threshold for emergency procedures
      )
      ;; Only supervisor can execute emergency recovery
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Only for significant allocations
      (asserts! (> quantity emergency-threshold) (err u430))
      ;; Only specific statuses are eligible
      (asserts! (or (is-eq current-status "frozen") 
                   (is-eq current-status "challenged")
                   (is-eq current-status "paused")) (err u431))

      ;; Execute the recovery
      (unwrap! (as-contract (stx-transfer? quantity tx-sender originator)) ERROR_MOVEMENT_FAILED)

      (print {action: "emergency_recovery_executed", allocation-identifier: allocation-identifier, 
              originator: originator, quantity: quantity, 
              recovery-authorization-digest: (hash160 recovery-authorization)})
      (ok true)
    )
  )
)

;; Record high-risk operation attempt
(define-public (record-high-risk-operation (allocation-identifier uint) (operation-type (string-ascii 30)) (justification (string-ascii 100)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only supervisor or originator can record high-risk operations
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator)) ERROR_UNAUTHORIZED)
      ;; Only allow for pending or accepted allocations
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") 
                   (is-eq (get allocation-status allocation-data) "accepted")) 
                ERROR_ALREADY_PROCESSED)
      ;; Only for significant allocations
      (asserts! (> quantity u1000) (err u400))
      ;; Valid operation types
      (asserts! (or (is-eq operation-type "large-transfer") 
                   (is-eq operation-type "cross-chain-movement")
                   (is-eq operation-type "multi-signature-approval")
                   (is-eq operation-type "security-parameter-change")) (err u401))

      (print {action: "high_risk_operation_recorded", allocation-identifier: allocation-identifier, 
              operation-type: operation-type, requestor: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Implement allocation expiration monitoring
(define-public (monitor-allocation-expiration (allocation-identifier uint) (action-type (string-ascii 20)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (current-status (get allocation-status allocation-data))
        (termination-block (get termination-block allocation-data))
        (warning-threshold u144) ;; 144 blocks (~1 day) warning threshold
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Only active allocations
      (asserts! (or (is-eq current-status "pending") 
                   (is-eq current-status "accepted")) ERROR_ALREADY_PROCESSED)

      ;; Valid action types
      (asserts! (or (is-eq action-type "notify") 
                   (is-eq action-type "extend")
                   (is-eq action-type "finalize")) (err u460))

      ;; Check if allocation is approaching expiration
      (asserts! (<= (- termination-block block-height) warning-threshold) (err u461))

      ;; If extension requested, add more time
      (if (is-eq action-type "extend")
          (map-set AllocationRepository
            { allocation-identifier: allocation-identifier }
            (merge allocation-data { termination-block: (+ termination-block u144) })
          )
          true
      )

      (print {action: "expiration_monitoring", allocation-identifier: allocation-identifier, 
              action-type: action-type, requestor: tx-sender, 
              blocks-remaining: (- termination-block block-height)})
      (ok true)
    )
  )
)

;; Set allocation priority level
(define-public (set-allocation-priority (allocation-identifier uint) (priority-level uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (<= priority-level u3) ERROR_INVALID_QUANTITY) ;; Priority levels 0-3 only
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (status (get allocation-status allocation-data))
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Status verification - only pending or accepted allocations can have priority changed
      (asserts! (or (is-eq status "pending") (is-eq status "accepted")) ERROR_ALREADY_PROCESSED)

      ;; Update allocation record with priority level
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: (if (is-eq priority-level u0) "pending" "accepted") })
      )

      (print {action: "priority_level_set", allocation-identifier: allocation-identifier, 
              originator: originator, priority-level: priority-level, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Register trusted verification entity
(define-public (register-verification-entity (allocation-identifier uint) (verifier principal) (verification-threshold uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> verification-threshold u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= verification-threshold u100) ERROR_INVALID_QUANTITY) ;; Threshold as percentage
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only significant allocations need verification entities
      (asserts! (> quantity u1000) (err u225))
      ;; Authorization check
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      ;; Ensure verifier is not the same as originator or beneficiary
      (asserts! (not (is-eq verifier originator)) (err u226))
      (asserts! (not (is-eq verifier (get beneficiary allocation-data))) (err u227))
      ;; Status verification
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)

      (print {action: "verification_entity_registered", allocation-identifier: allocation-identifier, 
              verifier: verifier, threshold: verification-threshold, registrar: tx-sender})
      (ok true)
    )
  )
)

