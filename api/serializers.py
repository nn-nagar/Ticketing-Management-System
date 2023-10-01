from rest_framework import serializers
from .models import MyUser, Location, Ticket


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = MyUser
        fields = ['email', 'date_of_birth', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        user = MyUser(email=self.validated_data['email'], date_of_birth=self.validated_data['date_of_birth'])
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password': 'Passwords must match.'})
        user.set_password(password)
        user.save()
        return user


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={"input_type": "password"}, required=True)
    new_password = serializers.CharField(style={"input_type": "password"}, required=True)

    def validate_current_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError({'current_password': 'Does not match'})
        return value


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = (
            "id",
            "location",
            "status",
            "date_created",
            "date_updated",
        )

    def save(self, validated_data):
        location = Location.objects.create(
            location=validated_data["location"],
            status=validated_data["status"],
            date_created=validated_data["date_created"],
            date_updated=validated_data["date_updated"]
        )
        location.save()
        return location.id

    def update(self, instance, validated_data):
        instance.location = validated_data["location"]
        instance.status = validated_data["status"]
        instance.date_created = validated_data["date_created"]
        instance.date_updated = validated_data["date_updated"]
        instance.save()
        return instance.id


class TicketSerializer(serializers.ModelSerializer):
    source = LocationSerializer(read_only=True)
    destination = LocationSerializer(read_only=True)

    class Meta:
        model = Ticket
        fields = (
            "id",
            "code",
            "source",
            "destination",
            "travel_date",
            "passenger_name",
            "Pricing",
            "seat_number",
            "date_created",
            "date_updated",
        )

    def save(self, validated_data):
        # import ipdb;
        # ipdb.set_trace()

        tkt = Ticket.objects.create(
            # code=validated_data["code"],
            # source=validated_data["subscriber_username"],
            # destination=validated_data.get("subscriber_address_line_1"),
            travel_date=validated_data.get('travel_date'),
            passenger_name=validated_data.get("passenger_name"),
            Pricing=validated_data.get("Pricing"),
            seat_number=validated_data.get("seat_number")
        )

        if validated_data["source"] == 'others':
            tkt.source = None
        else:
            source = Location.objects.get(
                id=validated_data["source"].get("id")
            )
            tkt.source = source

        if validated_data["destination"] == 'others':
            tkt.destination = None
        else:
            destination = Location.objects.get(
                id=validated_data["destination"].get("id")
            )
            tkt.destination = destination
        tkt.save()
        return tkt.id

    def update(self, instance, validated_data):
        # import ipdb;ipdb.set_trace()

        # instance.code = validated_data["code"]
        instance.travel_date = validated_data["travel_date"]
        instance.passenger_name = validated_data["passenger_name"]
        instance.Pricing = validated_data["Pricing"]
        instance.seat_number = validated_data["seat_number"]
        instance.save()
        source = Location.objects.get(id=validated_data["id"])
        instance.source = source
        destination = Location.objects.get(id=validated_data["id"])
        instance.destination = destination
        instance.save()
        return instance.id
