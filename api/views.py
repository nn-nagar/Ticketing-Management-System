from datetime import datetime
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.transaction import atomic
from .models import Ticket, Location
from .permissions import IsManager
from .utils import get_tokens_for_user
from .serializers import RegistrationSerializer, PasswordChangeSerializer, TicketSerializer, LocationSerializer
from rest_framework import status, permissions, generics
from django.http import JsonResponse, Http404
from rest_framework.generics import ListAPIView
from rest_framework.filters import SearchFilter, OrderingFilter


class RegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        if 'email' not in request.data or 'password' not in request.data:
            return Response({'msg': 'Credentials missing'}, status=status.HTTP_400_BAD_REQUEST)
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            auth_data = get_tokens_for_user(request.user)
            return Response({'msg': 'Login Success', **auth_data}, status=status.HTTP_200_OK)
        return Response({'msg': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'msg': 'Successfully Logged out'}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated, ]

    def post(self, request):
        serializer = PasswordChangeSerializer(context={'request': request}, data=request.data)
        serializer.is_valid(raise_exception=True)  # Another way to write is as in Line 17
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class LocationAPIView(APIView):
    permission_classes = [IsAuthenticated, ]
    # permission_classes = (permissions.AllowAny,)
    # permission_classes = (IsManager,)

    def get(self, request, *args, **kwargs):
        try:
            location_id = self.kwargs["id"]
            if Location.objects.filter(
                    id=location_id, is_deleted=False
            ).exists():
                tkt = Location.objects.get(
                    id=location_id, is_deleted=False
                )
                serializer = LocationSerializer(tkt)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            location = Location.objects.filter(is_deleted=False)
            serializer = LocationSerializer(location, many=True)
            return Response(serializer.data)

    @atomic
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = LocationSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        result = serializer.save(validated_data=data)
        location = Location.objects.get(id=result)

        serializer = LocationSerializer(location)
        print("serializer.data1-------->", serializer.data)
        print("serializer.data2 mail done-------->", serializer.data)
        return JsonResponse(serializer.data, safe=False)

    def delete(self, request, *args, **kwargs):
        try:
            location_id = self.kwargs["id"]
            ticket = Location.objects.get(id=location_id)
            ticket.is_deleted = True
            ticket.save()
            return Response(
                data={"message": "Location Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Location Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        try:
            info = Location.objects.get(
                id=id, is_deleted=False
            )
            serializer = LocationSerializer(info, data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.update(instance=info, validated_data=data)
            info = Ticket.objects.get(id=result)
            serializer = LocationSerializer(info)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"errors": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TicketAPIView(APIView):
    permission_classes = [IsAuthenticated, ]
    # permission_classes = (permissions.AllowAny,)
    # permission_classes = (IsManager,)

    def get(self, request, *args, **kwargs):
        try:
            ticket_id = self.kwargs["id"]
            if Ticket.objects.filter(
                    id=ticket_id, is_deleted=False
            ).exists():
                tkt = Ticket.objects.get(
                    id=ticket_id, is_deleted=False
                )
                serializer = TicketSerializer(tkt)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            tkt = Ticket.objects.filter(is_deleted=False)
            serializer = TicketSerializer(tkt, many=True)
            return Response(serializer.data)

    @atomic
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = TicketSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        result = serializer.save(validated_data=data)
        tkt = Ticket.objects.get(id=result)

        serializer = TicketSerializer(tkt)
        print("serializer.data1-------->", serializer.data)
        print("serializer.data2 mail done-------->", serializer.data)
        return JsonResponse(serializer.data, safe=False)

    def delete(self, request, *args, **kwargs):
        try:
            ticked_id = self.kwargs["id"]
            ticket = Ticket.objects.get(id=ticked_id)
            ticket.is_deleted = True
            ticket.save()
            return Response(
                data={"message": "Ticket Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Ticket Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def put(self, request, *args, **kwargs):
        data = self.request.data
        ticked_id = self.kwargs["id"]
        try:
            info = Ticket.objects.get(
                id=ticked_id, is_deleted=False
            )
            serializer = TicketSerializer(info, data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.update(instance=info, validated_data=data)
            info = Ticket.objects.get(id=result)
            serializer = TicketSerializer(info)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"errors": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TicketList(ListAPIView):
    permission_classes = [IsAuthenticated, ]
    # permission_classes = (IsManager,)
    # permission_classes = (permissions.AllowAny,)
    queryset = Ticket.objects.filter(is_deleted=False)
    serializer_class = TicketSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['passenger_name', 'travel_date', 'source__location', 'destination__location']
    ordering_fields = ['passenger_name', 'travel_date', 'source__location', 'destination__location']
    ordering = ['passenger_name', 'travel_date', 'source__location', 'destination__location']


class TicketDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated, ]
    # permission_classes = (permissions.AllowAny,)
    # permission_classes = (IsManager,)

    def get(self, request, *args, **kwargs):
        try:
            ticket_id = self.kwargs["id"]
            if Ticket.objects.filter(
                    id=ticket_id, is_deleted=False
            ).exists():
                tkt = Ticket.objects.get(
                    id=ticket_id, is_deleted=False
                )
                serializer = TicketSerializer(tkt)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            data = self.request.data
            start_date = data['start_date']
            end_date = data['end_date']
            tkt = Ticket.objects.filter(created_at__range=(start_date, end_date), is_deleted=False)
            serializer = TicketSerializer(tkt, many=True)
            return Response(serializer.data)
