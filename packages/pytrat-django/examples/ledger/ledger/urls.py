"""URL routes for the ledger example."""

from django.urls import path

from ledger import views

urlpatterns = [
    path("internal/transfer", views.transfer),
    path("internal/accounts/<str:source_account>/balance", views.balance),
    path("internal/health", views.health),
]
