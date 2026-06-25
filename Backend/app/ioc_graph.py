from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter()

class IocNode(BaseModel):
    id: str
    type: str

class IocEdge(BaseModel):
    source: str
    target: str

class IocGraphResponse(BaseModel):
    nodes: List[IocNode]
    edges: List[IocEdge]

@router.get("/ioc/graph", response_model=IocGraphResponse, summary="IOC Relationship Graph")
async def get_ioc_graph():
    """Return a static example IOC relationship graph for the bonus feature.
    Nodes include a domain, an IP, two malware families, and a CVE.
    Edges represent connections as described in the spec.
    """
    nodes = [
        IocNode(id="secure-login-update.com", type="domain"),
        IocNode(id="185.199.108.153", type="ip"),
        IocNode(id="LockBit", type="malware"),
        IocNode(id="FIN7", type="malware"),
        IocNode(id="CVE-2023-3519", type="cve"),
    ]
    edges = [
        IocEdge(source="secure-login-update.com", target="185.199.108.153"),
        IocEdge(source="185.199.108.153", target="LockBit"),
        IocEdge(source="185.199.108.153", target="FIN7"),
        IocEdge(source="LockBit", target="CVE-2023-3519"),
        IocEdge(source="FIN7", target="CVE-2023-3519"),
    ]
    return IocGraphResponse(nodes=nodes, edges=edges)
