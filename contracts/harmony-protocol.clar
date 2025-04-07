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

