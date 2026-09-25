"""Small inventory API used as the build target for the DevSecOps pipeline."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title="inventory-service", docs_url=None, redoc_url=None)

_ITEMS: dict[int, dict] = {1: {"id": 1, "name": "sensor", "qty": 4}}


class ItemIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 _-]+$")
    qty: int = Field(ge=0, le=10_000)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/items/{item_id}")
def get_item(item_id: int) -> dict:
    item = _ITEMS.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return item


@app.post("/items", status_code=201)
def create_item(body: ItemIn) -> dict:
    new_id = max(_ITEMS, default=0) + 1
    _ITEMS[new_id] = {"id": new_id, **body.model_dump()}
    return _ITEMS[new_id]
