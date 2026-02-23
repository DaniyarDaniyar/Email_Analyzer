# Python modules
from typing import Any

# Django REST Framework modules
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response as DRFResponse
from rest_framework.utils.serializer_helpers import ReturnList

class AbstractPageNumberPaginator(PageNumberPagination):
    """Abstract page number paginator with a unified response format."""

    page_size_query_param: str = "page_size"
    page_query_param: str = "page"

    def __init__(self, page_size: int = 6) -> None:
        self.page_size = page_size
        super().__init__()

    def get_paginated_response(self, data: ReturnList) -> DRFResponse:
        """Overriden method to return a paginated response with next/previous links and total page count."""
        response: DRFResponse = DRFResponse(
            {
                "pagination": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "count": self.page.paginator.num_pages,
                },
                "data": data,
            }
        )
        return response

    def get_dict_response(self, data: ReturnList) -> dict[str, Any]:
        """Get paginated response as a Dictionary with filled data."""

        return {
            "pagination": {
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "count": self.page.paginator.num_pages,
            },
            "data": data,
        }