from fastapi import FastAPI

app = FastAPI(title="councilbox-evid")


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.1.0"}
