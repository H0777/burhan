"""
Banking CSV Import Connector (T17)
Cyber-Forensic Auditing Framework - Specification §7 & T17 (R07, R08, R09, R11, R18)
Streaming CSV ingestion for institutional transactions with bounded limits,
strict timezone & scale validation, conflict rejection, and non-PII error reporting.
"""

import io
import csv
import uuid
import json
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import TransactionRecord, ImportBatchRecord
from app.schemas.identity import Identity
from app.schemas.transactions import (
    TransactionImportResponse,
    TransactionImportRowError,
)

MAX_ROWS_PER_FILE = 50000
EXPECTED_COLUMNS = [
    "external_id",
    "occurred_at",
    "sender_ref",
    "receiver_ref",
    "currency",
    "scale",
    "amount_minor",
]


class CsvImportError(Exception):
    pass


class OversizedFileError(CsvImportError):
    pass


class CsvImportConnector:
    def __init__(self, max_rows: int = MAX_ROWS_PER_FILE):
        self.max_rows = max_rows

    def parse_and_import(
        self,
        session: Session,
        identity: Identity,
        file_content: bytes,
        filename: str = "transactions.csv",
        source: str = "IQD_CSV",
    ) -> TransactionImportResponse:
        institution_id = identity.institution_id
        import_id = f"imp_{uuid.uuid4().hex[:16]}"

        try:
            text = file_content.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = file_content.decode("latin-1")
            except Exception as e:
                raise CsvImportError("CSV file encoding could not be decoded as UTF-8 or Latin-1")

        stream = io.StringIO(text)
        reader = csv.reader(stream)

        # Read header
        try:
            header = next(reader)
        except StopIteration:
            raise CsvImportError("Empty CSV file provided")

        header_clean = [h.strip().lower() for h in header]
        missing_cols = [c for c in EXPECTED_COLUMNS if c not in header_clean]
        if missing_cols:
            raise CsvImportError(f"Missing required columns in CSV header: {', '.join(missing_cols)}")

        col_indices = {c: header_clean.index(c) for c in EXPECTED_COLUMNS}

        total_rows = 0
        accepted_records = []
        errors: List[TransactionImportRowError] = []

        # In-batch duplicate tracker: external_id -> row_dict
        seen_in_batch: Dict[str, Dict[str, Any]] = {}

        # Query existing transactions for institution & source to detect conflicts
        existing_txs_map = {}

        for row_index, row in enumerate(reader, start=2):  # 1-indexed, header is row 1
            total_rows += 1
            if total_rows > self.max_rows:
                raise OversizedFileError(f"CSV exceeds maximum allowable limit of {self.max_rows} rows")

            if not row or all(not str(val).strip() for val in row):
                continue  # skip completely empty lines

            if len(row) < len(EXPECTED_COLUMNS):
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="MALFORMED_ROW",
                        message=f"Row has {len(row)} columns, expected at least {len(EXPECTED_COLUMNS)}",
                    )
                )
                continue

            # Extract fields
            ext_id = row[col_indices["external_id"]].strip()
            occurred_raw = row[col_indices["occurred_at"]].strip()
            sender = row[col_indices["sender_ref"]].strip()
            receiver = row[col_indices["receiver_ref"]].strip()
            currency = row[col_indices["currency"]].strip().upper()
            scale_raw = row[col_indices["scale"]].strip()
            amount_raw = row[col_indices["amount_minor"]].strip()

            # 1. external_id validation
            if not ext_id:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="MISSING_EXTERNAL_ID",
                        message="Field external_id is required and cannot be empty",
                    )
                )
                continue

            if len(ext_id) > 128:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="FIELD_TOO_LONG",
                        message="Field external_id exceeds maximum length of 128 characters",
                    )
                )
                continue

            # 2. occurred_at validation (MUST contain timezone)
            if not occurred_raw:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="MISSING_TIMESTAMP",
                        message="Field occurred_at is required",
                    )
                )
                continue

            try:
                # Replace 'Z' with '+00:00' for fromisoformat compatibility across Python versions
                iso_clean = occurred_raw
                if iso_clean.endswith("Z"):
                    iso_clean = iso_clean[:-1] + "+00:00"
                dt = datetime.fromisoformat(iso_clean)
                if dt.tzinfo is None:
                    errors.append(
                        TransactionImportRowError(
                            row_index=row_index,
                            error_code="MISSING_TIMEZONE",
                            message="Field occurred_at must explicitly include timezone offset (e.g. 'Z' or '+03:00')",
                        )
                    )
                    continue
            except Exception:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="INVALID_TIMESTAMP_FORMAT",
                        message="Field occurred_at is not a valid ISO 8601 timestamp",
                    )
                )
                continue

            # 3. sender & receiver ref validation
            if not sender or not receiver:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="MISSING_PARTY_REF",
                        message="Fields sender_ref and receiver_ref are required",
                    )
                )
                continue

            # 4. currency validation
            if not currency or len(currency) > 16:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="INVALID_CURRENCY",
                        message="Field currency must be valid code (e.g. IQD, USD)",
                    )
                )
                continue

            # 5. scale validation
            try:
                scale_val = int(scale_raw)
                if scale_val < 0 or scale_val > 18:
                    raise ValueError()
            except Exception:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="INVALID_SCALE",
                        message="Field scale must be an integer between 0 and 18",
                    )
                )
                continue

            # 6. amount_minor validation (must be positive integer)
            try:
                if "." in amount_raw:
                    raise ValueError("Minor amount cannot contain decimal points")
                amount_val = int(amount_raw)
                if amount_val <= 0:
                    raise ValueError("Minor amount must be strictly greater than 0")
            except Exception:
                errors.append(
                    TransactionImportRowError(
                        row_index=row_index,
                        error_code="INVALID_AMOUNT",
                        message="Field amount_minor must be a positive integer without decimals",
                    )
                )
                continue

            # 7. In-batch duplicate check
            row_data = {
                "occurred_at": dt,
                "sender_ref": sender,
                "receiver_ref": receiver,
                "currency": currency,
                "scale": scale_val,
                "amount_minor": amount_val,
            }

            if ext_id in seen_in_batch:
                prev = seen_in_batch[ext_id]
                if (
                    prev["amount_minor"] != amount_val
                    or prev["currency"] != currency
                    or prev["sender_ref"] != sender
                    or prev["receiver_ref"] != receiver
                ):
                    errors.append(
                        TransactionImportRowError(
                            row_index=row_index,
                            error_code="CONFLICT_DIFFERENT_DATA",
                            message=f"Duplicate external_id with conflicting transaction data in same file",
                        )
                    )
                    continue
                else:
                    # Identical row duplicate within same batch -> skip silently
                    continue
            seen_in_batch[ext_id] = row_data

            # 8. Database duplicate and conflict check
            if session is not None:
                existing = session.execute(
                    select(TransactionRecord).where(
                        TransactionRecord.institution_id == institution_id,
                        TransactionRecord.source == source,
                        TransactionRecord.external_id == ext_id,
                    )
                ).scalars().first()

                if existing:
                    # Compare critical financial fields
                    if (
                        existing.amount_minor != amount_val
                        or existing.currency != currency
                        or existing.sender_ref != sender
                        or existing.receiver_ref != receiver
                    ):
                        errors.append(
                            TransactionImportRowError(
                                row_index=row_index,
                                error_code="CONFLICT_DIFFERENT_DATA",
                                message=f"Row conflicts with existing transaction in database with different data; silent overwrite forbidden",
                            )
                        )
                        continue
                    else:
                        # Idempotent re-import: already safely recorded
                        continue

            # Record accepted
            tx_rec = TransactionRecord(
                id=f"tx_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                source=source,
                external_id=ext_id,
                occurred_at=dt,
                sender_ref=sender,
                receiver_ref=receiver,
                currency=currency,
                scale=scale_val,
                amount_minor=amount_val,
                status="RECORDED",
                created_at=datetime.now(timezone.utc),
            )
            accepted_records.append(tx_rec)

        accepted_count = len(accepted_records)
        rejected_count = len(errors)

        if rejected_count == 0:
            batch_status = "COMPLETED"
        elif accepted_count > 0 and rejected_count > 0:
            batch_status = "PARTIALLY_ACCEPTED"
        else:
            batch_status = "REJECTED"

        created_at_val = datetime.now(timezone.utc)

        # Batch insert accepted records if session provided
        if session is not None:
            for rec in accepted_records:
                session.add(rec)

            batch_rec = ImportBatchRecord(
                id=import_id,
                institution_id=institution_id,
                source=source,
                filename=filename,
                status=batch_status,
                total_rows=total_rows,
                accepted_rows=accepted_count,
                rejected_rows=rejected_count,
                errors_json=json.dumps([e.model_dump() for e in errors]),
                created_at=created_at_val,
            )
            session.add(batch_rec)
            session.flush()

        return TransactionImportResponse(
            import_id=import_id,
            institution_id=institution_id,
            filename=filename,
            status=batch_status,
            total_rows=total_rows,
            accepted_rows=accepted_count,
            rejected_rows=rejected_count,
            errors=errors,
            created_at=batch_rec.created_at,
        )
