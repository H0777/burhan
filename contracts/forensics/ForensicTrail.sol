// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ForensicTrail
 * @author H0777
 * @notice Immutable forensic evidence chain for cyber-auditing and legal proceedings
 * @dev Creates an unalterable, linked chain of digital evidence on the blockchain.
 *      Each evidence entry references the previous one via hash linking, forming
 *      a verifiable Chain of Custody that cannot be tampered with — even by admins.
 *
 * Key Properties:
 *   - Append-only: Evidence can never be modified or deleted
 *   - Hash-linked: Each entry contains the hash of the previous entry
 *   - Timestamped: Block timestamp provides court-admissible timing
 *   - Attributed: Every entry records who submitted the evidence
 *
 * Use Cases:
 *   - Recording suspicious transaction evidence
 *   - Documenting insider threat investigation steps
 *   - Building court-ready forensic dossiers
 *   - Regulatory compliance reporting (Central Bank / AML Authority)
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
        string evidenceType;        // e.g., "TRANSACTION_ANOMALY", "INSIDER_OVERRIDE", "AML_VIOLATION"
        string description;
        bytes32 evidenceHash;       // SHA-256 hash of off-chain evidence (documents, screenshots, etc.)
        bytes32 previousEntryHash;  // Hash of the previous evidence entry in this incident chain
        bytes32 entryHash;          // Hash of THIS entry (for chain verification)
    }

    struct Incident {
        uint256 id;
        string title;
        string severity;            // "LOW", "MEDIUM", "HIGH", "CRITICAL"
        address reportedBy;
        uint256 reportedAt;
        bool isOpen;
        uint256 evidenceCount;
    }

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public governance;
    uint256 private _incidentCounter;
    uint256 private _evidenceCounter;

    /// @notice Allowlist of authorized evidence writers (e.g. AuditEngine or official ingest service)
    mapping(address => bool) public isEvidenceWriter;

    /// @notice All incidents by ID
    mapping(uint256 => Incident) private _incidents;

    /// @notice Evidence entries per incident (ordered)
    mapping(uint256 => Evidence[]) private _evidenceChain;

    /// @notice All incident IDs
    uint256[] private _allIncidentIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event GovernanceTransferred(address indexed newGovernance);
    event EvidenceWriterUpdated(address indexed writer, bool authorized);

    event IncidentCreated(
        uint256 indexed incidentId,
        string title,
        string severity,
        address indexed reportedBy,
        uint256 timestamp
    );

    event EvidenceSubmitted(
        uint256 indexed incidentId,
        uint256 indexed evidenceId,
        address indexed submittedBy,
        string evidenceType,
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

    /**
     * @notice Transfer governance
     */
    function setGovernance(address _newGov) external onlyGovernance {
        require(_newGov != address(0), "ForensicTrail: zero address");
        governance = _newGov;
        emit GovernanceTransferred(_newGov);
    }

    /**
     * @notice Configure authorized evidence writer (governance only)
     */
    function setEvidenceWriter(address _writer, bool _authorized) external onlyGovernance {
        require(_writer != address(0), "ForensicTrail: zero address");
        isEvidenceWriter[_writer] = _authorized;
        emit EvidenceWriterUpdated(_writer, _authorized);
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Create a new forensic incident
     * @param _title Brief description of the incident
     * @param _severity Severity level: LOW, MEDIUM, HIGH, CRITICAL
     * @return incidentId The unique incident identifier
     */
    function createIncident(
        string calldata _title,
        string calldata _severity
    ) external returns (uint256 incidentId) {
        require(
            isEvidenceWriter[msg.sender] || msg.sender == governance,
            "ForensicTrail: caller is not authorized evidence writer"
        );
        require(bytes(_title).length > 0, "ForensicTrail: title required");
        require(bytes(_severity).length > 0, "ForensicTrail: severity required");

        _incidentCounter++;
        incidentId = _incidentCounter;

        _incidents[incidentId] = Incident({
            id: incidentId,
            title: _title,
            severity: _severity,
            reportedBy: msg.sender,
            reportedAt: block.timestamp,
            isOpen: true,
            evidenceCount: 0
        });

        _allIncidentIds.push(incidentId);

        emit IncidentCreated(
            incidentId,
            _title,
            _severity,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @notice Submit evidence to an incident's chain
     * @param _incidentId The incident to attach evidence to
     * @param _evidenceType Type classification (e.g., "TRANSACTION_ANOMALY")
     * @param _description Human-readable description of the evidence
     * @param _evidenceHash SHA-256 hash of any off-chain evidence files
     * @return evidenceId The unique evidence entry identifier
     */
    function submitEvidence(
        uint256 _incidentId,
        string calldata _evidenceType,
        string calldata _description,
        bytes32 _evidenceHash
    ) external returns (uint256 evidenceId) {
        require(isEvidenceWriter[msg.sender], "ForensicTrail: caller is not authorized evidence writer");
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        require(_incidents[_incidentId].isOpen, "ForensicTrail: incident is closed");
        require(bytes(_evidenceType).length > 0, "ForensicTrail: type required");
        require(bytes(_description).length > 0, "ForensicTrail: description required");

        _evidenceCounter++;
        evidenceId = _evidenceCounter;

        // Get previous entry hash for chain linking
        Evidence[] storage chain = _evidenceChain[_incidentId];
        bytes32 prevHash = chain.length > 0
            ? chain[chain.length - 1].entryHash
            : bytes32(0);

        // Compute this entry's hash (links to previous, creating tamper-evident chain)
        bytes32 entryHash = keccak256(abi.encodePacked(
            evidenceId,
            _incidentId,
            msg.sender,
            block.timestamp,
            _evidenceType,
            _description,
            _evidenceHash,
            prevHash
        ));

        Evidence memory newEvidence = Evidence({
            id: evidenceId,
            incidentId: _incidentId,
            submittedBy: msg.sender,
            timestamp: block.timestamp,
            evidenceType: _evidenceType,
            description: _description,
            evidenceHash: _evidenceHash,
            previousEntryHash: prevHash,
            entryHash: entryHash
        });

        chain.push(newEvidence);
        _incidents[_incidentId].evidenceCount++;

        emit EvidenceSubmitted(
            _incidentId,
            evidenceId,
            msg.sender,
            _evidenceType,
            entryHash,
            block.timestamp
        );
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
            msg.sender == incident.reportedBy,
            "ForensicTrail: only reporter can close"
        );

        incident.isOpen = false;
        emit IncidentClosed(_incidentId, msg.sender, block.timestamp);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    /**
     * @notice Get incident details
     */
    function getIncident(uint256 _incidentId) external view returns (Incident memory) {
        require(
            _incidentId > 0 && _incidentId <= _incidentCounter,
            "ForensicTrail: incident does not exist"
        );
        return _incidents[_incidentId];
    }

    /**
     * @notice Get the complete evidence chain for an incident
     */
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
     * @notice Verify the integrity of an evidence chain
     * @dev Recomputes each entry's hash and checks chain linking
     * @return isValid True if the entire chain is intact
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

            // Verify previous hash link
            bytes32 expectedPrevHash = i > 0 ? chain[i - 1].entryHash : bytes32(0);
            if (entry.previousEntryHash != expectedPrevHash) return false;

            // Recompute and verify entry hash
            bytes32 computedHash = keccak256(abi.encodePacked(
                entry.id,
                entry.incidentId,
                entry.submittedBy,
                entry.timestamp,
                entry.evidenceType,
                entry.description,
                entry.evidenceHash,
                entry.previousEntryHash
            ));
            if (entry.entryHash != computedHash) return false;
        }

        return true;
    }

    /**
     * @notice Get all incident IDs
     */
    function getAllIncidentIds() external view returns (uint256[] memory) {
        return _allIncidentIds;
    }

    /**
     * @notice Get total number of incidents
     */
    function totalIncidents() external view returns (uint256) {
        return _incidentCounter;
    }

    /**
     * @notice Get total number of evidence entries across all incidents
     */
    function totalEvidence() external view returns (uint256) {
        return _evidenceCounter;
    }
}
