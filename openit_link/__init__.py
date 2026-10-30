"""영역 통신 기반(D118). 받는 쪽은 `openit_link.server`, 보내는 쪽은 계약 클라이언트(`openit_link.clients`)."""
from .server import App, Request, Response, Route

__version__ = "0.1.0"
__all__ = ["App", "Request", "Response", "Route", "__version__"]
