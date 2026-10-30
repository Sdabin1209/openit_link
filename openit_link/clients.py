"""보내는 쪽(D118): 계약 패키지의 HTTP 클라이언트를 그대로 다시 내보낸다.
왜: 영역의 보내는 쪽 통신 컴포넌트가 의존하는 곳을 이 라이브러리 한 곳으로 모은다. 클라이언트 구현을 계약 밖으로 옮기는 일은
계약을 다시 열 때 한다(계약 v3.1.1 고정). 그때도 영역 코드는 이 import를 바꾸지 않는다.
"""
from boundary_contracts.clients import *  # noqa: F401,F403
from boundary_contracts.clients import __all__ as _all  # noqa: F401

__all__ = list(_all)
