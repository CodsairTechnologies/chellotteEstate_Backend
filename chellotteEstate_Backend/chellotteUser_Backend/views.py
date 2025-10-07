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
# from rest_framework.permissions import IsAuthenticated
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

#HOME BANNER
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

#HOME TIMELINE WITH ABOUT
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

#HOME GALLERY
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
                .limit(8)
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

#HOME_ESTATE ADRRESS
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

#HOME-FEATURED PRODUCTS
from sqlalchemy.sql.expression import func

class GetFeaturedProducts(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            products = (
                session.query(ProductSA)
                .filter(ProductSA.status == "Active", ProductSA.is_featured == True)
                .order_by(func.rand())  
                .limit(3)                
                .all()
            )

            if not products:
                return Response(
                    {
                        "response": "Warning",
                        "message": "No featured products found",
                        "count": 0,
                        "data": [],
                    },
                    status=200,
                )

            data = [
                {
                    "id": p.id,
                    "title": p.title,
                    "description": p.description,
                    "price": p.price,
                    "availability": p.availability,
                    "brand_name": p.brand_name,
                    "cover_image": p.cover_image,
                    "background_image": p.background_image,
                    "card_icon": p.card_icon,
                    "is_featured": p.is_featured,
                    "status": p.status,
                    "createdId": p.createdId,
                    "createddate": str(p.createddate),
                }
                for p in products
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

#HOME-TESTIMONIAL
class Get_Testimonials(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            testimonials = session.query(TestimonialSA).filter(
                TestimonialSA.status == "Active"
            ).order_by(TestimonialSA.id.desc()).all()

            if not testimonials:
                return Response({"response": "Warning", "message": "No testimonials found", "count": 0, "data": []}, status=200)

            data = [
                {
                    "id": t.id,
                    "name": t.name,
                    "testimony": t.testimony,
                    "profile_image": t.profile_image,
                    "status": t.status,
                    "createdId": t.createdId,
                    "createddate": str(t.createddate)
                }
                for t in testimonials
            ]

            return Response({"response": "Success", "count": len(data), "data": data}, status=200)

        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

#GALLERY PAGE
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

class FilterGalleryByName(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            # name = request..get("name")
            data = request.data

            name = data.get('name')
            if not name:
                return Response(
                    {"response": "Warning", "message": "Gallery name is required"},
                    status=200,
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

#GET GALLERY BOX
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

#ABOUT PAGE
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
                    "box_description":a.box_description,
                    "box_title":a.box_title,
                    "years_of_experience": a.years_of_experience,
                    "status": a.status,
                    "createdId": a.createdId,
                    "createddate": a.createddate,
                    "sec1_heading": a.sec1_heading,
                    "sec1_subheading": a.sec1_subheading,
                    "sec1_description": a.sec1_description,
                    "sec1_image": a.sec1_image,
                    "sec2_heading": a.sec2_heading,
                    "sec2_subheading": a.sec2_subheading,
                    "sec2_description": a.sec2_description,
                    "sec2_image": a.sec2_image,
                    "sec3_heading": a.sec3_heading,
                    "sec3_subheading": a.sec3_subheading,
                    "sec3_description": a.sec3_description,
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

#PRODUCT PAGE
class Get_Products(APIView):
    permission_classes = [AllowAny]

    def build_image_url(self, path):
        """Build a full image URL using MEDIA_URL."""
        if not path:
            return None
        return os.path.join(settings.MEDIA_URL, path).replace("\\", "/")

    def post(self, request):
        session = dbsession.Session()
        try:
            products = (
                session.query(ProductSA)
                .filter(ProductSA.status == "Active")
                .order_by(ProductSA.id.desc())
                .all()
            )

            if not products:
                return Response(
                    {"response": "Warning", "message": "No products found", "count": 0, "data": []},
                    status=200
                )

            data = []
            for p in products:
                data.append({
                    "id": p.id,
                    "productID": p.productID,
                    "title": p.title,
                    "description": p.description,
                    "price": str(p.price) if p.price else None,
                    "cover_image": self.build_image_url(p.cover_image),
                    "background_image": self.build_image_url(p.background_image),
                    "card_icon": self.build_image_url(p.card_icon),
                    "is_featured": p.is_featured,
                    "availability": p.availability,
                    "brand_name": p.brand_name,
                    "status": p.status,
                    "createdId": p.createdId,
                    "createddate": p.createddate,
                })

            return Response({
                "response": "Success",
                "count": len(data),
                "data": data
            }, status=200)

        except SQLAlchemyError as e:
            return Response({
                "response": "Error",
                "message": "Database error",
                "errors": str(e)
            }, status=500)

        except Exception as e:
            return Response({
                "response": "Error",
                "message": "Unexpected error",
                "errors": str(e)
            }, status=500)

        finally:
            session.close()

class FilterProducts(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            availability = request.data.get("availability")
            price_order = request.data.get("price_order")  # "low_to_high" or "high_to_low"

            query = session.query(ProductSA).filter(ProductSA.status == "Active")

            # Apply availability filter if provided
            if availability:
                query = query.filter(ProductSA.availability == availability)

            # Apply price ordering if provided
            if price_order == "low_to_high":
                query = query.order_by(ProductSA.price.asc())
            elif price_order == "high_to_low":
                query = query.order_by(ProductSA.price.desc())
            else:
                query = query.order_by(ProductSA.id.desc())  # default ordering

            products = query.all()

            if not products:
                return Response(
                    {
                        "response": "Warning",
                        "message": "No products found with given filters",
                        "count": 0,
                        "data": [],
                    },
                    status=200,
                )

            data = [
                {
                    "id": p.id,
                    "title": p.title,
                    "description": p.description,
                    "price": p.price,
                    "availability": p.availability,
                    "brand_name": p.brand_name,
                    "cover_image": p.cover_image,
                    "background_image": p.background_image,
                    "card_icon": p.card_icon,
                    "is_featured": p.is_featured,
                    "status": p.status,
                    "createdId": p.createdId,
                    "createddate": str(p.createddate),
                }
                for p in products
            ]

            return Response({"response": "Success", "count": len(data), "data": data}, status=200)

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

from sqlalchemy import or_

class SearchProducts(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            query_text = request.data.get("query")

            if not query_text:
                return Response(
                    {"response": "Warning", "message": "Search query is required"},
                    status=200,
                )

            products = (
                session.query(ProductSA)
                .filter(
                    ProductSA.status == "Active",
                    or_(
                        ProductSA.title.ilike(f"%{query_text}%"),
                        ProductSA.brand_name.ilike(f"%{query_text}%"),
                        # ProductSA.description.ilike(f"%{query_text}%"),
                    )
                )
                .order_by(ProductSA.id.desc())
                .all()
            )

            if not products:
                return Response(
                    {"response": "Warning", "message": "No products found", "count": 0, "data": []},
                    status=200,
                )

            data = [
                {
                    "id": p.id,
                    "title": p.title,
                    "description": p.description,
                    "price": p.price,
                    "availability": p.availability,
                    "brand_name": p.brand_name,
                    "cover_image": p.cover_image,
                    "background_image": p.background_image,
                    "card_icon": p.card_icon,
                    "is_featured": p.is_featured,
                    "status": p.status,
                    "createdId": p.createdId,
                    "createddate": str(p.createddate),
                }
                for p in products
            ]

            return Response({"response": "Success", "count": len(data), "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)

        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

#SEARCH AND FILTER TOGETHER
class SearchFilterProducts(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            query_text = request.data.get("query")       # Search query
            availability = request.data.get("availability")  # Filter by availability
            price_order = request.data.get("price_order")    # "low_to_high" or "high_to_low"

            query = session.query(ProductSA).filter(ProductSA.status == "Active")

            # Apply search if query exists
            if query_text:
                query = query.filter(
                    or_(
                        ProductSA.title.ilike(f"%{query_text}%"),
                        ProductSA.brand_name.ilike(f"%{query_text}%"),
                        ProductSA.description.ilike(f"%{query_text}%"),
                    )
                )

            # Apply availability filter if provided
            if availability:
                query = query.filter(ProductSA.availability == availability)

            # Apply price ordering if provided
            if price_order == "low_to_high":
                query = query.order_by(ProductSA.price.asc())
            elif price_order == "high_to_low":
                query = query.order_by(ProductSA.price.desc())
            else:
                query = query.order_by(ProductSA.id.desc())  # default ordering

            products = query.all()

            if not products:
                return Response(
                    {
                        "response": "Warning",
                        "message": "No products found matching the criteria",
                        "count": 0,
                        "data": [],
                    },
                    status=200,
                )

            data = [
                {
                    "id": p.id,
                    "title": p.title,
                    "description": p.description,
                    "price": p.price,
                    "availability": p.availability,
                    "brand_name": p.brand_name,
                    "cover_image": p.cover_image,
                    "background_image": p.background_image,
                    "card_icon": p.card_icon,
                    "is_featured": p.is_featured,
                    "status": p.status,
                    "createdId": p.createdId,
                    "createddate": str(p.createddate),
                }
                for p in products
            ]

            return Response({"response": "Success", "count": len(data), "data": data}, status=200)

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

#PRODUCT BOX
class Get_ProductPageBox(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(ProductPageBoxSA).filter(
                ProductPageBoxSA.status == "Active"
            ).order_by(ProductPageBoxSA.id.desc()).all()

            if not boxes:
                return Response({"response": "Warning", "message": "No data found", "count": 0, "data": []}, status=200)

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

#ADD ENQUIRY
class AddCustomerEnquiry(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data

            name = data.get('name')
            email = data.get('email')
            phoneNumber = data.get('phoneNumber')
            message = data.get('message')

            # #  Basic validation
            # if not all([name, email, message,phoneNumber]):
            #     return Response({
            #         "response": "Error",
            #         "message": "All fields (name, email, message,phone number) are required"
            #     }, status=400)

            #  Email format validation
            # EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
            # if not re.match(EMAIL_REGEX, email):
            #     return Response({
            #         "response": "Error",
            #         "message": "Please enter a valid email address"
            #     }, status=400)

            # Save enquiry to database
            enquiry = CustomerEnquiry(
                name=name,
                email=email,
                message=message,
                phoneNumber = phoneNumber,
                status = "Active",
                created_date=datetime.now()
            )
            session.add(enquiry)

            session.commit()
            return Response({
                "response": "Success",
                "message": "Enquiry submitted successfully"
                # "message": "Enquiry submitted and notification sent successfully"
            }, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error",
                "details": str(e)
            }, status=500)

        except Exception as e:
            session.rollback()
            return Response({
                'response': 'Error',
                'message': 'Unexpected error occurred',
                'Error': str(e)
            }, status=500)

        finally:
            session.close()

# class AddCustomerEnquiry(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         session = dbsession.Session()
#         try:
#             data = request.data

#             name = data.get('name')
#             email = data.get('email')
#             phoneNumber = data.get('phoneNumber')
#             message = data.get('message')
#             # --- Save enquiry to database ---
#             enquiry = CustomerEnquiry(
#                 name=name,
#                 email=email,
#                 message=message,
#                 phoneNumber=phoneNumber,
#                 status="Active",
#                 created_date=datetime.now()
#             )
#             session.add(enquiry)
#             session.commit()

#             # --- Fetch active admin emails ---
#             admin_emails = [
#                 admin.emailId for admin in session.query(SuperAdminDtl)
#                 .filter(SuperAdminDtl.status == "Active", SuperAdminDtl.emailId.isnot(None))
#                 .all()
#             ]

#             # --- Send email notification ---
#             if admin_emails:
#                 try:
#                     subject = f"📩 New Customer Enquiry from {name}"
#                     email_message = f"""
# Hello Admin,

# You have received a new customer enquiry.

# 👤 Name: {name}
# 📧 Email: {email}
# 📞 Phone: {phoneNumber}
# 💬 Message:
# {message}

# Submitted on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

# Regards,
# Your Website
# """
#                     send_mail(
#                         subject,
#                         email_message,
#                         settings.DEFAULT_FROM_EMAIL,
#                         admin_emails,
#                         fail_silently=False,
#                     )
#                 except Exception as e:
#                     # Email failure should not stop the API
#                     print("Email send failed:", e)

#             return Response({
#                 "response": "Success",
#                 "message": "Enquiry submitted successfully and notification sent to admin"
#             }, status=200)

#         except SQLAlchemyError as e:
#             session.rollback()
#             return Response({
#                 "response": "Error",
#                 "message": "Database error",
#                 "details": str(e)
#             }, status=500)

#         except Exception as e:
#             session.rollback()
#             return Response({
#                 'response': 'Error',
#                 'message': 'Unexpected error occurred',
#                 'Error': str(e)
#             }, status=500)

#         finally:
#             session.close()

class GetHomePlantations(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch all active highlights
            highlights = (
                session.query(HomePlantationSA)
                .filter(HomePlantationSA.status == "Active")
                .order_by(HomePlantationSA.order.asc())
                .all()
            )

            if not highlights:
                return Response(
                    {"response": "Warning", "message": "No plantation found", "count": 0, "highlights": []},
                    status=200
                )

            # Use the section title from the first record (since it’s shared)
            section_title = highlights[0].section_title if highlights[0].section_title else None

            data = [
                {
                    "id": h.id,
                    "title": h.title,
                    "description": h.description,
                    "image1": h.image1,
                    "image2": h.image2,
                    "image3": h.image3,
                    "order": h.order,
                    "status": h.status,
                }
                for h in highlights
            ]

            return Response(
                {
                    "response": "Success",
                    "section_title": section_title,
                    "count": len(data),
                    "Plantation": data,
                },
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


class GetTourismCards(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session = dbsession.Session()
        try:
            # cards = session.query(TourismCardSA).filter(
            #     TourismCardSA.status == "Active"
            # ).order_by(TourismCardSA.id.asc()).limit(4).all()
            cards = session.query(TourismCardSA).filter(
                TourismCardSA.status == "Active"
            ).order_by(TourismCardSA.id.asc()).order_by(func.rand()).limit(4).all()

            if not cards:
                return Response({"response": "Warning", "message": "No tourism cards found", "count": 0, "cards": []}, status=200)

            data = [
                {
                    "id": c.id,
                    "card_title": c.card_title,
                    "card_description": c.card_description,
                    "card_image": c.card_image,
                    "status": c.status,
                    "createdId": c.createdId,
                    "createddate": str(c.createddate)
                }
                for c in cards
            ]
            return Response({"response": "Success", "count": len(data), "cards": data}, status=200)
        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()
