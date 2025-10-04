from django.shortcuts import render
from django.db import models
from chellotteUser_Backend.models import*
from chellotteAdmin_Backend.models import*
from chellotteAdmin_Backend.views import*
# import razorpay
import requests
import traceback
from django.utils.html import escape

from io import BytesIO
import os
import sys
import uuid
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
import hmac
import hashlib
# from mankind_admin.models import Category,BannerSliders,AuthToken,Tax,ShippingCharge,ProductsImages,Products,PopularProduct,OutletSA,metalTypesSA,CareerSA,JobApplicationSA
import environ
import uuid
from rest_framework.permissions import IsAuthenticated
# from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.decorators import api_view, permission_classes, renderer_classes,authentication_classes
import json,jwt
from sqlalchemy.exc import SQLAlchemyError
from rest_framework.response import Response
from chellotteEstate_Backend import dbsession
from django.http import HttpResponse
import traceback
from sqlalchemy import create_engine, MetaData, Table, DDL
from sqlalchemy.orm import sessionmaker
from os.path import basename
from datetime import datetime     
from datetime import datetime, timedelta

from sqlalchemy.orm import aliased
from django.core.files.uploadedfile import InMemoryUploadedFile


from django.contrib.auth import authenticate
import math
import random
from datetime import timedelta,date
# import datetime
from django.utils import timezone
from django.template.loader import get_template
from sqlalchemy.orm.exc import NoResultFound
import os
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
import secrets
import re 
import time
from sqlalchemy import Time as SQLAlchemyTime
from sqlalchemy.orm import joinedload
import inflect
from django.conf import settings  
from jwt.exceptions import ExpiredSignatureError, DecodeError 
import string
from django.core.files.storage import FileSystemStorage
from sqlalchemy import func
import traceback
from asgiref.sync import async_to_sync
import pandas as pd 
import numpy as np
from io import BytesIO 
from openpyxl import load_workbook 
from collections import defaultdict
from sqlalchemy.types import Float  
from sqlalchemy import func, and_
from django.core.management import call_command
from django.http import HttpResponseNotFound
from rest_framework import status
from django.http import StreamingHttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
#from .models import Country
#from .database import async_sessionmaker
from sqlalchemy.future import select
import asyncio
from sqlalchemy import or_, and_ 
import calendar
from django.utils.translation import gettext as _
from django.db import connection, DatabaseError
from sqlalchemy import create_engine, inspect, text
from sqlalchemy import text
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from django.utils.timezone import make_aware
from num2words import num2words
from babel.numbers import format_decimal

from io import BytesIO
from babel.dates import format_datetime

# import firebase_admin
# from firebase_admin import credentials, messaging
# from firebase.firebase import send_fcm_message
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from PIL import Image
import math

env = environ.Env()
environ.Env.read_env()

class UserGetActiveBanner(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            sql_query = text("""
                SELECT * 
                FROM banner_tbl
                WHERE status = 'Active'
                ORDER BY id DESC
            """)

            result = session.execute(sql_query)
            rows = result.fetchall()

            if not rows:
                return Response({
                    'response': 'Warning',
                    'message': 'No active banners found'
                }, status=status.HTTP_200_OK)

            data = [dict(row._mapping) for row in rows]

            return Response({
                'response': 'Success',
                'banners': data
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'Error',
                'message': 'Database error occurred',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                'response': 'Error',
                'message': 'Unexpected error',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class User_GetEstateWithTimeline(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            estate = session.query(EstateInfoSA).filter(
                EstateInfoSA.status == "Active"
            ).order_by(EstateInfoSA.id.desc()).all()

            if not estate:
                return Response(
                    {"response": "Warning", "message": "No estate found"},
                    status=200,
                )

            # estate_data = {
            #     "estateId": estate.id,
            #     "title": estate.title,
            #     "subtitle": "About the Estate",   # since it's static
            #     "description": estate.description,
            #     "image_left": estate.image_left,
            #     "image_right": estate.image_right,
            # }

            estate_data = [
                {
                    "estateId": e.id,
                    "title": e.title,
                    "subtitle": "About the Estate",  
                    "description": e.description,
                    "image_left": e.image_left,
                    "image_right": e.image_right,
                }
                for e in estate
            ]

            # Fetch ordered timelines
            timelines = session.query(TimelineEventSA).filter(
                TimelineEventSA.status == "Active"
            ).order_by(TimelineEventSA.order.asc()).all()

            timeline_data = [
                {
                    "id" : t.id,
                    "timelineId": t.timelineId,
                    "year_or_period": t.year_or_period,
                    "title": t.title,
                    "description": t.description,
                    "order": t.order,
                }
                for t in timelines
            ]

            return Response(
                {"response": "success","estate": estate_data, "timeline": timeline_data},
                status=200,
            )

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()


class User_GalleryPage(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            galleries = (
                session.query(GallerySA)
                .filter(GallerySA.status == "Active")
                .order_by(GallerySA.id.desc())
                .all()
            )
            if not galleries:  
                return Response(
                    {
                        "response": "Warning",
                        "message": "No gallery data found",
                        "count": 0,
                        "data": [],
                    },
                    status=200,
                )
            data = [
                {
                    "id": g.id,
                    "title": g.title,
                    "image": g.image,
                    "status": g.status,
                    "createdId": g.createdId,
                    "createddate": g.createddate,
                }
                for g in galleries
            ]

            return Response(
                {"response": "Success", "count": len(data), "data": data},
                status=200,
            )

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )
        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )
        finally:
            session.close()

class home_GetGallery(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch latest 6 active galleries
            galleries = (
                session.query(GallerySA)
                .filter(GallerySA.status == "Active")
                .order_by(GallerySA.id.desc())
                .limit(6)
                .all()
            )

            if not galleries:  
                return Response(
                    {
                        "response": "Warning",
                        "message": "No gallery data found",
                        "count": 0,
                        "data": [],
                    },
                    status=200,
                )

            data = [
                {
                    "id": g.id,
                    "title": g.title,
                    "image": g.image,
                    "status": g.status,
                    "createdId": g.createdId,
                    "createddate": g.createddate,
                }
                for g in galleries
            ]

            return Response(
                {"response": "Success", "count": len(data), "data": data},
                status=200,
            )

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )
        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )
        finally:
            session.close()

class FilterGalleryByName(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            name = request.query_params.get("name")

            if not name:
                return Response(
                    {"response": "Error", "message": "Gallery name is required"},
                    status=400,
                )

            galleries = session.query(GallerySA).filter(
                GallerySA.title.ilike(f"%{name}%"),
                GallerySA.status != "Deleted"
            ).all()

            if not galleries:
                return Response(
                    {"response": "Warning", "message": "No galleries found with that name"},
                    status=200,
                )

            data = [
                {
                    "galleryId": g.id,
                    "title": g.title,
                    "image": g.image,
                    "status": g.status,
                }
                for g in galleries
            ]

            return Response({"response": "Success", "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class GetEstateAddress(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")

            query = session.query(EstateAddressSA).filter(EstateAddressSA.status != "Deleted")

            if estate_id: 
                query = query.filter(EstateAddressSA.id == estate_id)

            estates = query.order_by(EstateAddressSA.id.desc()).all()

            if not estates:
                return Response(
                    {"response": "Warning", "message": "No estate address found", "count": 0, "data": []},
                    status=200
                )

            data = [
                {
                    "id": e.id,
                    "email": e.email,
                    "phone_number": e.phone_number,
                    "address": e.address,
                    "map_location": e.map_location,
                    "status": e.status,
                    "createdId": e.createdId,
                    "createddate": e.createddate,
                }
                for e in estates
            ]

            return Response(
                {"response": "Success", "count": len(data), "data": data},
                status=200
            )

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500
            )

        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500
            )

        finally:
            session.close()

class GalleryBox(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(GalleryBoxSA).filter(
                GalleryBoxSA.status == "Active"
            ).order_by(GalleryBoxSA.id.desc()).all()

            if not boxes:
                return Response(
                    {"response": "Warning", "message": "No gallery boxes found", "count": 0, "data": []},
                    status=200
                )

            data = [
                {
                    "id": b.id,
                    "title": b.title,
                    "description": b.description,
                    "status": b.status,
                    "createdId": b.createdId,
                    "createddate": b.createddate,
                }
                for b in boxes
            ]

            return Response({"response": "Success", "count": len(data), "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetAboutPage(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch all non-deleted AboutPage records
            about_list = session.query(AboutPageSA)\
                .filter(AboutPageSA.status == "Active")\
                .order_by(AboutPageSA.id.desc())\
                .all()

            if not about_list:
                return Response(
                    {
                        "response": "Warning",
                        "message": "No AboutPage data found",
                        "count": 0,
                        "data": []
                    },
                    status=200
                )

            data = []
            for a in about_list:
                data.append({
                    "id": a.id,
                    "box_title": "About Us",
                    "box_description":a.box_description,
                    "years_of_experience": a.years_of_experience,
                    "status": a.status,
                    "createdId": a.createdId,
                    "createddate": a.createddate,
                    "sec1_heading": a.sec1_heading,
                    "sec1_subheading": a.sec1_subheading,
                    "sec1_image": a.sec1_image,
                    "sec2_heading": a.sec2_heading,
                    "sec2_subheading": a.sec2_subheading,
                    "sec2_image": a.sec2_image,
                    "sec3_heading": a.sec3_heading,
                    "sec3_subheading": a.sec3_subheading,
                    "sec3_image": a.sec3_image,
                })

            return Response(
                {"response": "Success", "count": len(data), "data": data},
                status=200
            )

        except SQLAlchemyError as e:
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500
            )

        except Exception as e:
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500
            )

        finally:
            session.close()