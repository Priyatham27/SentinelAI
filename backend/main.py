from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from firewall import FirewallEngine
from logs import LogStore

app = FastAPI(title="SentinelAI Firewall API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall = FirewallEngine()
log_store = LogStore()


class PromptRequest(BaseModel):
    prompt: str
    api_key: str = ""
    hybrid_mode: bool = True


class AgentRequest(BaseModel):
    prompt: str
    api_key: str


@app.get("/")
def root():
    return {"status": "SentinelAI Firewall is ACTIVE", "version": "1.0.0"}


@app.post("/analyze")
async def analyze_prompt(req: PromptRequest):
    """
    Main firewall endpoint.
    Runs the full pipeline: inspect → detect → enforce → sanitize → log
    """
    result = await firewall.run_pipeline(
        prompt=req.prompt,
        api_key=req.api_key,
        hybrid_mode=req.hybrid_mode
    )
    log_store.add(req.prompt, result)
    return result


@app.post("/agent")
async def agent_query(req: AgentRequest):
    """
    Simulated AI Agent endpoint.
    Prompt passes through firewall first — only safe prompts reach the agent.
    """
    from agent import AIAgent

    # Step 1: Firewall check
    firewall_result = await firewall.run_pipeline(
        prompt=req.prompt,
        api_key=req.api_key,
        hybrid_mode=True
    )
    log_store.add(req.prompt, firewall_result)

    # Step 2: If blocked, agent never sees it
    if firewall_result["detected"]:
        return {
            "agent_response": None,
            "firewall": firewall_result,
            "message": "Prompt blocked by SentinelAI. Agent was NOT reached."
        }

    # Step 3: Safe — forward to agent
    agent = AIAgent(api_key=req.api_key)
    agent_response = await agent.respond(firewall_result["sanitized_prompt"] or req.prompt)
    return {
        "agent_response": agent_response,
        "firewall": firewall_result,
        "message": "Prompt cleared by SentinelAI. Agent responded safely."
    }


@app.get("/logs")
def get_logs():
    return log_store.get_all()


@app.delete("/logs")
def clear_logs():
    log_store.clear()
    return {"message": "Logs cleared"}


@app.get("/stats")
def get_stats():
    return log_store.get_stats()
