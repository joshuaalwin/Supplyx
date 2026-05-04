import io
import os

from minio import Minio
from minio.error import S3Error

_client: Minio | None = None


def _get_client() -> Minio:
    global _client
    if _client is None:
        _client = Minio(
            endpoint=os.environ.get("MINIO_ENDPOINT", "minio:9000"),
            access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
            secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
            secure=False,
        )
    return _client


def upload_bytes(bucket: str, key: str, data: bytes) -> None:
    _get_client().put_object(bucket, key, io.BytesIO(data), length=len(data))


def download_bytes(bucket: str, key: str) -> bytes:
    response = _get_client().get_object(bucket, key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def object_exists(bucket: str, key: str) -> bool:
    try:
        _get_client().stat_object(bucket, key)
        return True
    except S3Error:
        return False
