from typing import Optional, Dict
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest


class AntiVirus(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(AntiVirus, self).__init__(config)

    def start(self) -> None:
        pass

    def execute(self, request: ServiceRequest) -> None:
        pass

    def stop(self) -> None:
        pass
