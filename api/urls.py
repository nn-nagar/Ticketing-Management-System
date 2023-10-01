from django.urls import path
from .views import RegistrationView, LoginView, LogoutView, ChangePasswordView, TicketAPIView, TicketList, \
    TicketDashboardAPIView, LocationAPIView
from rest_framework_simplejwt import views as jwt_views

# app_name = 'api'

urlpatterns = [
    path('accounts/register/', RegistrationView.as_view(), name='register'),
    path('accounts/login/', LoginView.as_view(), name='register'),
    path('accounts/logout/', LogoutView.as_view(), name='register'),
    path('accounts/change-password/', ChangePasswordView.as_view(), name='register'),
    path('accounts/token-refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('location/', LocationAPIView.as_view(), name='location'),
    path('location/<int:id>/', LocationAPIView.as_view(), name='location'),
    path('ticket/', TicketAPIView.as_view(), name='ticket'),
    path('ticket/<uuid:id>/', TicketAPIView.as_view(), name='ticket'),
    path('ticket-list/', TicketList.as_view(), name='ticket-filter-list'),
    path('ticket-dashboard-api/', TicketDashboardAPIView.as_view(), name='ticket-dashboard-api'),
]
