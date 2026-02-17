
import json
import io
import gzip
import base64
from typing import Any, Dict


def _zip_text(text_input: str) -> str:
    buf = io.BytesIO()

    with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9) as f:
        f.write(text_input.encode('utf-8'))

    compressed_bytes = buf.getvalue()
    base64_encoded = base64.b64encode(compressed_bytes).decode('utf-8')

    return base64_encoded

def package_scan_report(vt3_results: Dict[str, Any]):
    return _zip_text(
            json.dumps([
                f
                for f in vt3_results
            ]
        )
    )
