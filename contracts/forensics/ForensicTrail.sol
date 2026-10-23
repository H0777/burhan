// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libraries/EvidenceHashing.sol";

/**
 * @title ForensicTrail
 * @author H0777
 * @notice Immutable forensic evidence chain for cyber-auditing and legal proceedings (V2)
 * @dev Creates an unalterable, linked chain of digital evidence on the blockchain.
 *      Uses canonical Evidence V2 hashing and deduplication per Design Specification §5 & §6.
 */
contract ForensicTrail {

    // ============================================================
    // STRUCTS
    // ============================================================

    struct Evidence {
        uint256 id;
        uint256 incidentId;
        address submittedBy;
        uint256 timestamp;
        bytes32 evidenceTypeHash;
        bytes32 descriptionHash;
        bytes32 evidenceHash;       // SHA-256 hash of off-chain evidence (file/payload)
        bytes32 previousEntryHash;  // Hash of the previous evidence entry in this incident chain
        bytes32 entryHash;          // Canonical V2 entry hash (EvidenceHashing)
    }

    struct Incident {
        uint256 id;
        bytes32 titleHash;
        bytes32 severityHash;
        address reportedBy;
        uint256 reportedAt;
        bool isOpen;
        uint256 evidenceCount;
    }

    struct DedupRecord {
        bytes32 payloadHash;
        uint256 evidenceId;
        bytes32 entryHash;
        address submittedBy;
        bool exists;
    }

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public governance;
    uint256 private _incidentCounter;
    uint256 private _evidenceCounter;

    /// @notice Allowlist of authorized evidence writers (AuditEngine, ingest service)
    mapping(address => bool) public isEvidenceWriter;

    /// @notice All incidents by ID
    mapping(uint256 => Incident) private _incidents;

    /// @notice Evidence entries per incident (ordered)
    mapping(uint256 => Evidence[]) private _evidenceChain;

    /// @notice Deduplication tracking by anchorRequestId
    mapping(bytes32 => DedupRecord) private _anchorRequests;

    /// @notice All incident IDs
    uint256[] private _allIncidentIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event GovernanceTransferred(address indexed newGovernance);
    event EvidenceWriterUpdated(address indexed writer, bool authorized);

    event IncidentCreated(
        uint256 indexed incidentId,
        bytes32 titleHash,
        bytes32 severityHash,
        address indexed reportedBy,
        uint256 timestamp
    );

    event EvidenceSubmitted(
        uint256 indexed incidentId,
        uint256 indexed evidenceId,
        address indexed submittedBy,
        bytes32 evidenceTypeHash,
        bytes32 entryHash,
        uint256 timestamp
    );

    event IncidentClosed(
        uint256 indexed incidentId,
        address indexed closedBy,
        uint256 timestamp
    );

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyGovernance() {
        require(msg.sender == governance, "ForensicTrail: caller is not governance");
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(address _governance) {
        require(_governance != address(0), "ForensicTrail: invalid governance");
        governance = _governance;
    }

    // ============================================================
    // GOVERNANCE CONFIGURATION
    // ============================================================

    function setGovernance(address _newGov) external onlyGovernance {
        require(_newGov != address(0), "ForensicTrail: zero address");
        governance = _newGov;
        emit GovernanceTransferred(_newGov);
    }

    function setEvidenceWriter(address _writer, bool _authorized) external onlyGovernance {
        require(_writer != address(0), "ForensicTrail: zero address");
        isEvidenceWriter[_writer] = _authorized;
        emit EvidenceWriterUpdated(_writer, _authorized);
    }

    // ============================================================
    // CORE FUNCTIONS (V2)
    // ============================================================

    /**
     * @notice Create a new forensic incident with hashed metadata (no raw sensitive data on-chain)
     * @param _titleHash Keccak256 hash of title
     * @param _severityHash Keccak256 hash of severity
     */
    function createIncident(
        bytes32 _titleHash,
        bytes32 _severityHash
    ) external returns (uint256 incidentId) {
        require(
            isEvidenceWriter[msg.sender] || msg.sender == governance,
            "ForensicTrail: caller is not authorized evidence writer"
        );
        require(_titleHash != bytes32(0), "ForensicTrail: title required");
        require(_severityHash != bytes32(0), "ForensicTrail: severity required");

        _incidentCounter++;
        incidentId = _incidentCounter;

        _incidents[incidentId] = Incident({
            id: incidentId,
            titleHash: _titleHash,
            severityHash: _severityHash,
            reportedBy: msg.sender,
            reportedAt: block.timestamp,
            isOpen: true,
            evidenceCount: 0
        });

        _allIncidentIds.push(incidentId);

        emit IncidentCreated(
            incidentId,
            _titleHash,
            _severityHash,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @notice Submit evidence to an incident's chain with deduplication and canonical V2 hashing
     * @param _incidentId Target incident ID
     * @param _anchorRequestId Unique operation ID for idempotency/deduplication
     * @param _evidenceTypeHash Keccak256 hash of evidence type classification
     * @param _descriptionHash Keccak256 hash of description
     * @param _fileSha256 SHA-256 hash of off-chain payload/file
     * @return evidenceId The unique evidence entry identifier
     */
    function submitEvidence(
        uint256 _incidentId,
        bytes32 _anchorRequestId,
        bytes32 _evidenceTypeHash,
        bytes32 _descriptionHash,
        bytes32 _fileSha256
    ) external returns (uint256 evidenceId) {
        require(_anchorRequestId != bytes32(0), "ForensicTrail: anchorRequestId required");

        bytes32 payloadHash = keccak256(
            abi.encode(_incidentId, _evidenceTypeHash, _descriptionHash, _fileSha256)
        );

        // Deduplication check
        if (_anchorRequests[_anchorRequestId].exists) {
            DedupRecord storage rec = _anchorRequests[_anchorRequestId];
            require(rec.submittedBy == msg.sender, "ForensicTrail: anchorRequestId submittedBy mismatch");
            require(rec.payloadHash == payloadHash, "ForensicTrail: anchorRequestId payload mismatch");
            return rec.evidenceId; // Idempotent return without incrementing or emitting event
        }

        require(isEvidenceWriter[msg.sender], "ForensicTrail: caller is not authorized evidence writer");
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        require(_incidents[_incidentId].isOpen, "ForensicTrail: incident is closed");
        require(_evidenceTypeHash != bytes32(0), "ForensicTrail: type required");
        require(_descriptionHash != bytes32(0), "ForensicTrail: description required");

        _evidenceCounter++;
        evidenceId = _evidenceCounter;

        // Get previous entry hash for chain linking
        Evidence[] storage chain = _evidenceChain[_incidentId];
        bytes32 prevHash = chain.length > 0
            ? chain[chain.length - 1].entryHash
            : bytes32(0);

        // Compute canonical V2 entry hash
        EvidenceHashing.EvidenceV2 memory entryV2 = EvidenceHashing.EvidenceV2({
            schemaVersion: EvidenceHashing.SCHEMA_VERSION,
            chainId: block.chainid,
            contractAddress: address(this),
            incidentId: _incidentId,
            evidenceId: evidenceId,
            submittedBy: msg.sender,
            timestamp: block.timestamp,
            evidenceTypeHash: _evidenceTypeHash,
            descriptionHash: _descriptionHash,
            evidenceHash: _fileSha256,
            previousEntryHash: prevHash
        });

        bytes32 entryHash = EvidenceHashing.hashEntry(entryV2);

        Evidence memory newEvidence = Evidence({
            id: evidenceId,
            incidentId: _incidentId,
            submittedBy: msg.sender,
            timestamp: block.timestamp,
            evidenceTypeHash: _evidenceTypeHash,
            descriptionHash: _descriptionHash,
            evidenceHash: _fileSha256,
            previousEntryHash: prevHash,
            entryHash: entryHash
        });

        chain.push(newEvidence);
        _incidents[_incidentId].evidenceCount++;

        // Store deduplication record
        _anchorRequests[_anchorRequestId] = DedupRecord({
            payloadHash: payloadHash,
            evidenceId: evidenceId,
            entryHash: entryHash,
            submittedBy: msg.sender,
            exists: true
        });

        emit EvidenceSubmitted(
            _incidentId,
            evidenceId,
            msg.sender,
            _evidenceTypeHash,
            entryHash,
            block.timestamp
        );
    }

    /**
     * @notice Get evidence details by idempotent anchorRequestId
     */
    function getEvidenceByRequestId(bytes32 _anchorRequestId)
        external
        view
        returns (
            uint256 evidenceId,
            bytes32 entryHash,
            address submittedBy,
            bool exists
        )
    {
        DedupRecord storage rec = _anchorRequests[_anchorRequestId];
        return (rec.evidenceId, rec.entryHash, rec.submittedBy, rec.exists);
    }

    /**
     * @notice Close an incident (no more evidence can be added)
     * @param _incidentId The incident to close
     */
    function closeIncident(uint256 _incidentId) external {
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        Incident storage incident = _incidents[_incidentId];
        require(incident.isOpen, "ForensicTrail: already closed");
        require(
            msg.sender == incident.reportedBy || msg.sender == governance,
            "ForensicTrail: only reporter can close"
        );

        incident.isOpen = false;
        emit IncidentClosed(_incidentId, msg.sender, block.timestamp);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getIncident(uint256 _incidentId) external view returns (Incident memory) {
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        return _incidents[_incidentId];
    }

    function getEvidenceChain(uint256 _incidentId)
        external
        view
        returns (Evidence[] memory)
    {
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        return _evidenceChain[_incidentId];
    }

    /**
     * @notice Verify the cryptographic integrity of an evidence chain using Evidence V2 hashing
     */
    function verifyChainIntegrity(uint256 _incidentId)
        external
        view
        returns (bool isValid)
    {
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );

        Evidence[] storage chain = _evidenceChain[_incidentId];
        if (chain.length == 0) return true;

        for (uint256 i = 0; i < chain.length; i++) {
            Evidence storage entry = chain[i];

            bytes32 expectedPrevHash = i > 0 ? chain[i - 1].entryHash : bytes32(0);
            if (entry.previousEntryHash != expectedPrevHash) return false;

            EvidenceHashing.EvidenceV2 memory entryV2 = EvidenceHashing.EvidenceV2({
                schemaVersion: EvidenceHashing.SCHEMA_VERSION,
                chainId: block.chainid,
                contractAddress: address(this),
                incidentId: entry.incidentId,
                evidenceId: entry.id,
                submittedBy: entry.submittedBy,
                timestamp: entry.timestamp,
                evidenceTypeHash: entry.evidenceTypeHash,
                descriptionHash: entry.descriptionHash,
                evidenceHash: entry.evidenceHash,
                previousEntryHash: entry.previousEntryHash
            });

            if (entry.entryHash != EvidenceHashing.hashEntry(entryV2)) return false;
        }

        return true;
    }

    function getAllIncidentIds() external view returns (uint256[] memory) {
        return _allIncidentIds;
    }

    function totalIncidents() external view returns (uint256) {
        return _incidentCounter;
    }

    function totalEvidence() external view returns (uint256) {
        return _evidenceCounter;
    }
}
