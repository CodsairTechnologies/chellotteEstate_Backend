from django.shortcuts import render
from django.db import models
from chellotteAdmin_Backend.models import*
import environ
# from sqlalchemy import case
# from django.utils.html import strip_tags
from django.db.models import Sum, Avg
from sqlalchemy import text  
# from rest_framework import status
# from sqlalchemy import func, extract
# import calendar
# import mimetypes  # Add this at the top of your file
from PIL import Image
from datetime import datetime, timedelta
from sqlalchemy.orm import aliased
# from rest_framework.parsers import MultiPartParser, FormParser
# from django.core.files.uploadedfile import UploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
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
from chellotteEstate_Backend.adminrestframeworkTokenAuthenticaion import TokenAuthentication
from django.contrib.auth import authenticate
#from CeeKeDayon_Backend.JSONDateSerializer import JSONDateEncoder
import math
import random
from datetime import timedelta,date
import datetime
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
# from channels.layers import get_channel_layer
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
# from sqlalchemy import or_, and_ 
import calendar
from django.utils.translation import gettext as _
# from django.db import connection, DatabaseError
# from sqlalchemy import create_engine, inspect, text
# from sqlalchemy import text
# from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
# from django.utils.timezone import make_aware
# from num2words import num2words
# from babel.numbers import format_decimal
import sys
from io import BytesIO
from babel.dates import format_datetime
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image

env = environ.Env()
environ.Env.read_env()

categoryFolder='media/'
bannerFolder='media/'


def get_current_date():
    return datetime.datetime.now().strftime('%d-%m-%Y')
    current_date = get_current_date()

def generateOtp():
    digits = "0123456789"
    OTP = ""
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP

def senduserOTP(params):
    try:
        ctx = {'OTP': params['otp_val']}

        plaintext = get_template('email/email.txt')
        htmly = get_template('email/email.html')
        subject = 'Welcome to MANKIND TALKS'
        from_email = 'anupamaminnu2002@gmail.com'
        to = params['emailId']

        text_content = plaintext.render(ctx)
        html_content = htmly.render(ctx)

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_content, "text/html")

        try:
            msg.send()
            return True
        except Exception as email_error:
            print("Email sending error:", email_error)
            return False

    except Exception as e:
        print("General error in senduserOTP:", e)
        return False

def generate_key():
    random_key = secrets.token_hex(4) 
    return random_key
# ---Login ----
@api_view(['POST'])
@permission_classes([AllowAny])
def SuperAdminAuthentication(request):
    session = dbsession.Session()
    try:
        username = request.data['username']
        password = request.data['password']

        user = session.query(SuperAdminDtl).filter(SuperAdminDtl.username == username).one_or_none()
        current_date = datetime.datetime.now().replace(microsecond=0)

        if user and user.check_password(password):
            if user.status == "Active":
                try:
                    expiry_time = datetime.datetime.now() + timedelta(minutes=600)
                    payload = {
                        'loginId': user.loginId,
                        'expiry': expiry_time.strftime("%Y-%m-%d %H:%M:%S")
                    }

                    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                    session.query(SuperAdminDtl).filter(SuperAdminDtl.loginId == user.loginId).update({'lastlogined': current_date})
                    #session.query(AuthToken).filter_by(loginId=user.loginId).delete()

                    auth_token = AuthToken()
                    auth_token.key = token
                    auth_token.created = current_date
                    auth_token.loginId = user.loginId
                    session.add(auth_token)
                    session.commit()
                    # fcm_token = request.data['fcm_token']
                    # session.query(AuthToken).filter(AuthToken.loginId == user.loginId).update({'fcm_token': fcm_token})
                    # session.commit()
                    history = SuperAdminLoginHistoryDtl(
                        loginId=user.loginId,
                        logineddate=current_date.date(),
                        loginedtime=current_date.time(),
                        createddate=current_date,
                        # loginbrowser=request.data['loginbrowser']
                    )
                    session.add(history)
                    session.commit()

                    admin_details = {
                        'token': token,
                        'username': user.username,
                        'EmailId': user.emailId,
                        'loginId': user.loginId,
                        'type': 'SuperAdmin',
                        'status': 'Active',
                        'token_expiry': expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'expiry_time': expiry_time,
                        # 'loginbrowser': history.loginbrowser
                    }
                    if all(admin_details.values()):
                        return Response({'response': 'Success', 'logindetails': admin_details})
                    else:
                        return Response({'response': 'Error', 'message': 'Invalid admin details found.'})
                    
                except Exception as e:
                    session.rollback()
                    return Response({'response': 'Error', 'message': 'Cannot login now. Please try again later...!', 'Error': str(e)})
            else:
                return Response({'status': 'Error', 'message': 'Your account is inactive. Please contact the admin.'})
        else:
            return Response({'status': 'Error', 'message': 'Please check your credentials'})
    except SQLAlchemyError as e:
        traceback.print_exc()
        session.rollback()
        return Response({'response': 'Error', 'message': 'Something went wrong please try again after sometime', 'Error': str(e)})
    except Exception as e:
        traceback.print_exc()
        session.rollback()
        return Response({'response': 'Error', 'message': 'Something went wrong please try again after sometime', 'Error': str(e)})
    finally:
        session.close()
        
 
#------------ Forgot Password -------
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def AdminforgotPassword(request):
    session = dbsession.Session()
    
    try:
        emailId = request.data.get('emailId')
        if not emailId:
            return Response({'response': 'Error', 'message': 'Email ID is required'}, status=400)

        try:
            admin = session.query(SuperAdminDtl).filter(SuperAdminDtl.emailId == emailId).one()
        except NoResultFound:
            admin = None

        if not admin:
            return Response({'response': 'Error', 'message': 'An account with this email does not exist'}, status=200)

        Otp = generateOtp()
        key = generate_key()
        otp_cre_time = datetime.datetime.now().replace(microsecond=0)
        otp_expire_time = otp_cre_time + timedelta(minutes=5)

        otpParams = {
            "otp_val": Otp,
            "otp_cre_time": otp_cre_time,
            "otp_expire_time": otp_expire_time,
            "emailId": emailId
        }

        if Otp:
            result = senduserOTP(otpParams)

            if result is True:
                otpObj = OTP()
                otpObj.emailId = emailId
                otpObj.otp = Otp
                otpObj.key = key
                otpObj.createddate = datetime.datetime.now()
                otpObj.date_time = datetime.datetime.now()
                otpObj.status = 'Active'

                session.add(otpObj)
                session.commit()

                return Response({
                    'response': 'Success',
                    'message': 'OTP sent successfully',
                    'key': key
                }, status=200)
            else:
                return Response({
                    'response': 'Error',
                    'message': 'Unable to send OTP. Please check the email address.'
                }, status=200)
        else:
            return Response({
                'response': 'Error',
                'message': 'Unable to generate OTP. Please try again later.'
            }, status=200)

    except SQLAlchemyError as e:
        session.rollback()
        return Response({'response': 'Error', 'message': 'Database error occurred', 'error': str(e)}, status=500)

    except Exception as e:
        session.rollback()
        return Response({'response': 'Error', 'message': 'Unexpected error occurred', 'error': str(e)}, status=500)

    finally:
        session.close()
        
        
@api_view(['GET', 'POST'])
@permission_classes([AllowAny, ])
def AdminverifyOtp(request):
    session = dbsession.Session()
    otp = request.data['otp']
    key = request.data['key']
    emailId = request.data['emailId']
    try:

        admin = session.query(OTP).filter(OTP.emailId == emailId, OTP.key == key).one()

        date_time_str = admin.date_time
        date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S.%f')
        date_time = timezone.make_aware(date_time_obj)

        current_time = timezone.now()
        expiration_time = timezone.timedelta(minutes=1)
        
        if current_time - date_time > expiration_time:
            session.close()
            return Response({'response': 'Error', "message": "OTP expired"}, status=200)
        else:
            if admin.otp == otp:
                return Response({'response': 'Success', 'message': 'OTP Verified'})
            else:
                session.close()
                return Response({'response': 'Error', 'message': 'Incorrect OTP'})
        
    
    except SQLAlchemyError as e:
        print(e)
        return Response({'response': 'Error', 'message': 'Try again after sometime'})

    except Exception as e:
        print(e)
        session.rollback()
        return Response({'response': 'Error', 'message': 'Something went wrong please try again after sometime', 'Error': str(e)})

    finally:
        session.close()

@api_view(['GET', 'POST'])
@permission_classes([AllowAny, ])
def AdminchangePassword(request):
        session = dbsession.Session()

        try:
            emailId = request.data.get('emailId')
            newPwd = request.data.get('newpwd')
            confirmPwd = request.data.get('confirmpwd')

            # Check if any field is missing
            if not emailId or not newPwd or not confirmPwd:
                return Response({'response': 'Error', 'message': 'emailId, new password, and confirm password are required.'}, status=400)

            # Check if passwords match
            if newPwd != confirmPwd:
                return Response({'response': 'Error', 'message': 'New password and confirm password do not match.'}, status=200)

            admin = session.query(SuperAdminDtl).filter(SuperAdminDtl.emailId == emailId).one_or_none()

            if admin:
                hashed_password = make_password(newPwd)
                admin.password = hashed_password
                session.add(admin)

                password_obj = PasswordChangeHistory()
                password_obj.status = 'Active'
                password_obj.changeddate = datetime.datetime.now()
                password_obj.loginId = admin.loginId
                password_obj.createddate = datetime.datetime.now()
                password_obj.type = admin.type
                session.add(password_obj)

                session.commit()
                return Response({'response': 'Success', 'message': 'Password changed successfully'},status=200)
            else:
                return Response({'response': 'Error', 'message': 'Admin not found'}, status=404)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Database error. Please try again later.', 'Error': str(e)}, status=500)

        except Exception as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Something went wrong. Please try again later.', 'Error': str(e)}, status=500)

        finally:
            session.close()

# -----Profile ------
class GetProfile(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            sql_query = """
                SELECT * 
                FROM super_admintbl
                WHERE status = 'Active'
                ORDER BY id DESC
            """

            result = session.execute(sql_query)
            rows = result.fetchall()

            if not rows:
                return Response({
                    'response': 'Error',
                    'message': 'No admin found'
                }, status=status.HTTP_200_OK)

            data = [dict(row) for row in rows]

            return Response({
                'response': 'Success',
                'admin': data
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

class AddEditBanner(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)


    def generate_banner_id(self, session):
        latest = session.query(Banner).order_by(Banner.id.desc()).first()
        number = int(latest.bannerId.replace('BAN', '')) + 1 if latest and latest.bannerId else 1
        return f"BAN{str(number).zfill(2)}"

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            banner_id = data.get('bannerId')  # Used for edit
            title = data.get('title')
            description = data.get('description')
            # link = data.get('link')
            createdId = data.get('createdId')
            image_file = request.FILES.get('bannerurl')

            image_url = None
            if image_file and image_file.name != 'undefined':
                image = Image.open(image_file)
                image_io = BytesIO()

                if image.mode in ("RGBA", "P"):
                    image = image.convert("RGB")

                image.save(image_io, format='WEBP', quality=75)
                image_io.seek(0)

                new_image_name = os.path.splitext(image_file.name)[0] + '.webp'
                compressed_image = InMemoryUploadedFile(
                    image_io, None, new_image_name, 'image/webp', sys.getsizeof(image_io), None
                )

                # fs = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

                fs = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

                filename = fs.save(compressed_image.name, compressed_image)
                image_url = fs.url(filename)

            # --------- Edit Logic ---------
            if banner_id:
                banner = session.query(Banner).filter(
                    Banner.bannerId == banner_id,
                    Banner.status != 'Deleted'
                ).first()

                if not banner:
                    return Response({'response': 'Error', 'message': 'Banner not found or already deleted'}, status=404)

                if title:
                    banner.title = title
                if description:
                    banner.description = description
                # if link:
                #     banner.link = link
                if image_url:
                    banner.bannerurl = image_url

                session.commit()
                return Response({'response': 'Success', 'message': 'Banner updated successfully'}, status=200)

            # --------- Add Logic ---------
            # if not image_url:
            #     return Response({'response': 'Error', 'message': 'Banner image is required for adding'}, status=400)

            banner = Banner(
                bannerId=self.generate_banner_id(session),
                title=title,
                description=description,
                # link=link,
                bannerurl=image_url,
                status='Active',
                createdId=createdId,
                createddate=datetime.date.today()
            )

            session.add(banner)
            session.commit()
            return Response({'response': 'Success', 'message': 'Banner added successfully'}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Database error', 'errors': str(e)}, status=500)

        except Exception as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Unexpected error', 'errors': str(e)}, status=500)

        finally:
            session.close()
       
class GetBanner(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            sql_query = text("""
                SELECT * 
                FROM banner_tbl
                WHERE status != 'Deleted'
                ORDER BY id DESC
            """)

            result = session.execute(sql_query)
            rows = result.fetchall()

            if not rows:
                return Response({
                    'response': 'Warning',
                    'message': 'No data found'
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
                'message': 'Something went wrong',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class GetActiveBanner(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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
                    'response': 'Warningr',
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
            
class GetBannerById(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            banner_id = request.data.get('banner_id')
            id = request.data.get('id')

            if not id or not banner_id:
                return Response({
                    'response': 'Error',
                    'message': 'Both id and banner_id are required'
                }, status=status.HTTP_400_BAD_REQUEST)

            sql_query = text("""
                SELECT * 
                FROM banner_tbl
                WHERE id = :id AND bannerId = :banner_id
            """)

            result = session.execute(sql_query, {'id': id, 'banner_id': banner_id})
            row = result.fetchone()

            if not row:
                return Response({
                    'response': 'Warning',
                    'message': 'Banner not found'
                }, status=status.HTTP_200_OK)

            data = dict(row._mapping)

            return Response({
                'response': 'Success',
                'banner': data
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
                'message': 'Something went wrong',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class UpdateBannerStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            banner_id = request.data.get('banner_id')
            status_value = request.data.get('status')

            if not banner_id or not status_value:
                return Response({
                    'response': 'Error',
                    'message': 'banner_id and status are required'
                }, status=status.HTTP_400_BAD_REQUEST)

            banner = session.query(Banner).filter_by(bannerId=banner_id).first()

            if not banner:
                return Response({
                    'response': 'Error',
                    'message': 'Banner not found'
                }, status=status.HTTP_200_OK)

            banner.status = status_value
            session.commit()

            return Response({
                'response': 'Success',
                'message': "Updated Successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'Error',
                'message': 'Database error',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class DeleteBanner(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            banner_id = request.data.get('banner_id')

            if not banner_id:
                return Response({
                    'response': 'Error',
                    'message': 'banner_id is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            banner = session.query(Banner).filter_by(bannerId=banner_id).first()

            if not banner:
                return Response({
                    'response': 'Error',
                    'message': 'Banner not found'
                }, status=status.HTTP_200_OK)

            banner.status = 'Deleted'
            session.commit()

            return Response({
                'response': 'Success',
                'message': 'Banner deleted successfully'
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'Error',
                'message': 'Database error',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class AddEditEstate(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def compress_image(self, image_file):
        """
        Compress the uploaded image into WEBP format
        """
        image = Image.open(image_file)
        image_io = BytesIO()

        # Convert RGBA/Palette → RGB for WEBP compatibility
        if image.mode in ("RGBA", "P"):
            image = image.convert("RGB")

        # Save compressed version
        image.save(image_io, format="WEBP", quality=75)  # adjust quality (50-80) if needed
        image_io.seek(0)

        # Rename file extension to .webp
        new_image_name = os.path.splitext(image_file.name)[0] + ".webp"

        return InMemoryUploadedFile(
            image_io,
            None,
            new_image_name,
            "image/webp",
            sys.getsizeof(image_io),
            None,
        )

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            estate_id = data.get("id")  # Primary key for edit
            title = data.get("title")
            description = data.get("description")
            createdId = data.get("createdId")
            image_left = request.FILES.get("image_left")
            image_right = request.FILES.get("image_right")

            # FileSystemStorage for saving images
            fs = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

            # Compress and save left image
            image_left_url = None
            if image_left and image_left.name != "undefined":
                compressed_left = self.compress_image(image_left)
                filename = fs.save(compressed_left.name, compressed_left)
                image_left_url = fs.url(filename)

            # Compress and save right image
            image_right_url = None
            if image_right and image_right.name != "undefined":
                compressed_right = self.compress_image(image_right)
                filename = fs.save(compressed_right.name, compressed_right)
                image_right_url = fs.url(filename)

            # ---------- Edit Logic ----------
            if estate_id:
                estate = session.query(EstateInfoSA).filter(
                    EstateInfoSA.id == estate_id,
                    EstateInfoSA.status != "Deleted"
                ).first()

                if not estate:
                    return Response(
                        {"response": "warning", "message": "Estate not found"},
                        status=200,
                    )

                if title:
                    estate.title = title
                if description:
                    estate.description = description
                if image_left_url:
                    estate.image_left = image_left_url
                if image_right_url:
                    estate.image_right = image_right_url

                session.commit()
                return Response(
                    {"response": "Success", "message": "Estate updated successfully"},
                    status=200,
                )

            # ---------- Add Logic ----------
            estate = EstateInfoSA(
                title=title,
                description=description,
                image_left=image_left_url,
                image_right=image_right_url,
                status="Active",
                createdId=createdId,
                createddate=datetime.date.today(),
            )
            session.add(estate)
            session.commit()

            return Response(
                {"response": "Success", "message": "Estate added successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()


class AddEditTimeline(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def generate_timeline_id(self, session):
        latest = session.query(TimelineEventSA).order_by(TimelineEventSA.id.desc()).first()
        number = int(latest.timelineId.replace("TLN", "")) + 1 if latest and latest.timelineId else 1
        return f"TLN{str(number).zfill(2)}"

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            timeline_id = data.get("timelineId")  # For edit
            year_or_period = data.get("year_or_period")
            title = data.get("title")
            description = data.get("description")
            order = data.get("order")
            createdId = data.get("createdId")

            if not year_or_period:
                return Response(
                    {"response": "Error", "message": "year_or_period is required"},
                    status=400
                )

            # ---------- Edit Logic ----------
            if timeline_id:
                timeline = session.query(TimelineEventSA).filter(
                    TimelineEventSA.timelineId == timeline_id,
                    TimelineEventSA.status != "Deleted"
                ).first()

                if not timeline:
                    return Response(
                        {"response": "warning", "message": "Timeline not found"},
                        status=200,
                    )

                # Check duplicate for other records
                duplicate = session.query(TimelineEventSA).filter(
                    TimelineEventSA.year_or_period == year_or_period,
                    TimelineEventSA.timelineId != timeline_id,
                    TimelineEventSA.status != "Deleted"
                ).first()
                if duplicate:
                    return Response(
                        {"response": "Warning", "message": "year_or_period already exists"},
                        status=200
                    )

                timeline.year_or_period = year_or_period
                if title:
                    timeline.title = title
                if description:
                    timeline.description = description
                if order:
                    timeline.order = order

                session.commit()
                return Response(
                    {"response": "Success", "message": "Timeline updated successfully"},
                    status=200,
                )

            # Check duplicate
            duplicate = session.query(TimelineEventSA).filter(
                TimelineEventSA.year_or_period == year_or_period,
                TimelineEventSA.status != "Deleted"
            ).first()
            if duplicate:
                return Response(
                    {"response": "Warning", "message": "year_or_period already exists"},
                    status=200
                )

            if order is None:
                max_order = session.query(func.max(TimelineEventSA.order)).scalar() or 0
                order = max_order + 1

            timeline = TimelineEventSA(
                timelineId=self.generate_timeline_id(session),
                year_or_period=year_or_period,
                title=title,
                description=description,
                order=order,
                status="Active",
                createdId=createdId,
                createddate=datetime.date.today(),
            )
            session.add(timeline)
            session.commit()

            return Response(
                {"response": "Success", "message": "Timeline added successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

# class AddEditTimeline(APIView):
#     permission_classes = (IsAuthenticated,)
#     authentication_classes = (TokenAuthentication,)

#     def generate_timeline_id(self, session):
#         latest = session.query(TimelineEventSA).order_by(TimelineEventSA.id.desc()).first()
#         number = int(latest.timelineId.replace("TLN", "")) + 1 if latest and latest.timelineId else 1
#         return f"TLN{str(number).zfill(2)}"

#     def post(self, request):
#         session = dbsession.Session()
#         try:
#             data = request.data
#             timeline_id = data.get("timelineId")  # For edit
#             year_or_period = data.get("year_or_period")
#             title = data.get("title")
#             description = data.get("description")
#             order = data.get("order")
#             createdId = data.get("createdId")

#             # ---------- Edit Logic ----------
#             if timeline_id:
#                 timeline = session.query(TimelineEventSA).filter(
#                     TimelineEventSA.timelineId == timeline_id,
#                     TimelineEventSA.status != "Deleted"
#                 ).first()

#                 if not timeline:
#                     return Response(
#                         {"response": "Error", "message": "Timeline not found"},
#                         status=404,
#                     )

#                 if year_or_period:
#                     timeline.year_or_period = year_or_period
#                 if title:
#                     timeline.title = title
#                 if description:
#                     timeline.description = description
#                 if order:
#                     timeline.order = order

#                 session.commit()
#                 return Response(
#                     {"response": "Success", "message": "Timeline updated successfully"},
#                     status=200,
#                 )

#             # ---------- Add Logic ----------
#             if order is None:
#                 max_order = session.query(func.max(TimelineEventSA.order)).scalar() or 0
#                 order = max_order + 1

#             timeline = TimelineEventSA(
#                 timelineId=self.generate_timeline_id(session),
#                 year_or_period=year_or_period,
#                 title=title,
#                 description=description,
#                 order=order,
#                 status="Active",
#                 createdId=createdId,
#                 createddate=datetime.date.today(),
#             )
#             session.add(timeline)
#             session.commit()

#             return Response(
#                 {"response": "Success", "message": "Timeline added successfully"},
#                 status=200,
#             )

#         except SQLAlchemyError as e:
#             session.rollback()
#             return Response(
#                 {"response": "Error", "message": "Database error", "errors": str(e)},
#                 status=500,
#             )

#         except Exception as e:
#             session.rollback()
#             return Response(
#                 {"response": "Error", "message": "Unexpected error", "errors": str(e)},
#                 status=500,
#             )

#         finally:
#             session.close()

class Active_GetEstateWithTimeline(APIView):
    permission_classes = (AllowAny,)  # Public endpoint
    authentication_classes = ()

    def post(self, request):
        session = dbsession.Session()
        try:
            # Get the latest active estate (since only one estate exists)
            estate = session.query(EstateInfoSA).filter(
                EstateInfoSA.status == "Active"
            ).order_by(EstateInfoSA.id.desc()).first()

            if not estate:
                return Response(
                    {"response": "Error", "message": "No estate found"},
                    status=404,
                )

            # Build estate dict
            estate_data = {
                "estateId": f"EST{str(estate.id).zfill(2)}",
                "title": estate.title,
                "subtitle": "About the Estate",   # since it's static
                "description": estate.description,
                "image_left": estate.image_left,
                "image_right": estate.image_right,
            }

            # Fetch ordered timelines
            timelines = session.query(TimelineEventSA).filter(
                TimelineEventSA.status == "Active"
            ).order_by(TimelineEventSA.order.asc()).all()

            timeline_data = [
                {
                    "timelineId": t.timelineId,
                    "year_or_period": t.year_or_period,
                    "title": t.title,
                    "description": t.description,
                    "order": t.order,
                }
                for t in timelines
            ]

            return Response(
                {"estate": estate_data, "timeline": timeline_data},
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

class GetEstate(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # Get the latest active estate (since only one exists)
            estates = session.query(EstateInfoSA).filter(
                EstateInfoSA.status != "Deleted"
            ).order_by(EstateInfoSA.id.desc()).all()

            if not estates:
                return Response(
                    {"response": "Warning", "message": "No estate found"},
                    status=200,
                )

            # estate_data = {
            #     "estateId": estate.id,
            #     "title": estate.title,
            #     # "subtitle": "About the Estate",   # static if needed
            #     "description": estate.description,
            #     "image_left": estate.image_left,
            #     "image_right": estate.image_right,
            # }
            estate_data = [
                {
                    "estateId": e.id,
                    "title": e.title,
                    "description": e.description,
                    "image_left": e.image_left,
                    "image_right": e.image_right,
                }
                for e in estates
            ]

            return Response({"response": "success","estate": estate_data}, status=200)

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

class GetTimeline(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            timelines = session.query(TimelineEventSA).filter(
                TimelineEventSA.status != "Deleted"
            ).order_by(TimelineEventSA.order.asc()).all()

            if not timelines:
                return Response(
                    {"response": "Warning", "message": "No timeline events found"},
                    status=200,
                )

            timeline_data = [
                {
                    "timelineId": t.timelineId,
                    "year_or_period": t.year_or_period,
                    "title": t.title,
                    "description": t.description,
                    "order": t.order,
                    "Status": t.status,
                    "createdDate": t.createddate
                }
                for t in timelines
            ]

            return Response({"response": "Success","timeline": timeline_data}, status=200)

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

class Active_GetEstate(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # Get the latest active estate (since only one exists)
            estate = session.query(EstateInfoSA).filter(
                EstateInfoSA.status == "Active"
            ).order_by(EstateInfoSA.id.desc()).all()

            if not estate:
                return Response(
                    {"response": "Error", "message": "No estate found"},
                    status=404,
                )

            # estate_data = {
            #     "estateId": f"EST{str(estate.id).zfill(2)}",
            #     "title": estate.title,
            #     "subtitle": "About the Estate",   # static if needed
            #     "description": estate.description,
            #     "image_left": estate.image_left,
            #     "image_right": estate.image_right,
            # }

            estate_data = [
                {
                    "estateId": e.id,
                    "title": e.title,
                    "description": e.description,
                    "image_left": e.image_left,
                    "image_right": e.image_right,
                }
                for e in estate
            ]

            return Response({"estate": estate_data}, status=200)

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

class Active_GetTimeline(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            timelines = session.query(TimelineEventSA).filter(
                TimelineEventSA.status == "Active"
            ).order_by(TimelineEventSA.order.asc()).all()

            if not timelines:
                return Response(
                    {"response": "Warning", "message": "No timeline events found"},
                    status=200,
                )

            timeline_data = [
                {
                    "timelineId": t.timelineId,
                    "year_or_period": t.year_or_period,
                    "title": t.title,
                    "description": t.description,
                    "order": t.order,
                    "Status": t.status,
                    "createdDate": t.createddate,
                }
                for t in timelines
            ]

            return Response({"timeline": timeline_data}, status=200)

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

class GetEstateById(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")

            if not estate_id:
                return Response({
                    "response": "Error",
                    "message": "Estate id is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            sql_query = text("""
                SELECT * 
                FROM estateinfo_tbl
                WHERE id = :id AND status != 'Deleted'
            """)

            result = session.execute(sql_query, {"id": estate_id})
            row = result.fetchone()

            if not row:
                return Response({
                    "response": "Warning",
                    "message": "Estate not found"
                }, status=status.HTTP_200_OK)

            data = dict(row._mapping)

            return Response({
                "response": "Success",
                "estate": data
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "response": "Error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class GetTimelineById(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # timeline_id = request.data.get("id")
            timeline_code = request.data.get("timelineId")

            if not timeline_code:
                return Response({
                    "response": "Error",
                    "message": "timelineId is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            sql_query = text("""
                SELECT * 
                FROM timeline_tbl
                WHERE timelineId = :timelineId AND status != 'Deleted'
            """)

            result = session.execute(sql_query, {"timelineId": timeline_code})
            row = result.fetchone()

            if not row:
                return Response({
                    "response": "Warning",
                    "message": "Timeline not found"
                }, status=status.HTTP_200_OK)

            data = dict(row._mapping)

            return Response({
                "response": "Success",
                "timeline": data
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "response": "Error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class UpdateEstateStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("estate_id")
            status_value = request.data.get("status")

            if not estate_id or not status_value:
                return Response({
                    "response": "Error",
                    "message": "estate_id and status are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            estate = session.query(EstateInfoSA).filter_by(id=estate_id).first()

            if not estate:
                return Response({
                    "response": "Error",
                    "message": "Estate not found"
                }, status=status.HTTP_200_OK)

            estate.status = status_value
            session.commit()

            return Response({
                "response": "Success",
                "message": "Estate status updated successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class UpdateTimelineStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            timeline_id = request.data.get("timeline_id")
            status_value = request.data.get("status")

            if not timeline_id or not status_value:
                return Response({
                    "response": "Error",
                    "message": "timeline_id and status are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            timeline = session.query(TimelineEventSA).filter_by(timelineId=timeline_id).first()

            if not timeline:
                return Response({
                    "response": "Warning",
                    "message": "Timeline not found"
                }, status=status.HTTP_200_OK)

            timeline.status = status_value
            session.commit()

            return Response({
                "response": "Success",
                "message": "Timeline status updated successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class DeleteEstate(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("estate_id")

            if not estate_id:
                return Response({
                    "response": "Error",
                    "message": "estate_id is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            estate = session.query(EstateInfoSA).filter_by(id=estate_id).first()

            if not estate:
                return Response({
                    "response": "Error",
                    "message": "Estate not found"
                }, status=status.HTTP_200_OK)

            estate.status = "Deleted"
            session.commit()

            return Response({
                "response": "Success",
                "message": "Estate deleted successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class DeleteTimeline(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            timeline_id = request.data.get("timeline_id")

            if not timeline_id:
                return Response({
                    "response": "Error",
                    "message": "timeline_id is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            timeline = session.query(TimelineEventSA).filter_by(timelineId=timeline_id).first()

            if not timeline:
                return Response({
                    "response": "Warning",
                    "message": "Timeline not found"
                }, status=status.HTTP_200_OK)

            timeline.status = "Deleted"
            session.commit()

            return Response({
                "response": "Success",
                "message": "Timeline deleted successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "Error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()

class AddEditGallery(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def compress_image(self, uploaded_file, quality=70):
        """
        Compress uploaded image and return compressed file path
        """
        try:
            # Open image with Pillow
            img = Image.open(uploaded_file)
            img_io = BytesIO()

            # Convert all images to JPEG for compression (unless PNG with transparency)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")

            img.save(img_io, format="JPEG", quality=quality, optimize=True)
            return ContentFile(img_io.getvalue(), name=uploaded_file.name)
        except Exception as e:
            raise Exception(f"Image compression failed: {str(e)}")

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            gallery_id = data.get("id")  # for edit
            title = data.get("title")
            status = data.get("status", "Active")
            createdId = data.get("createdId")
            createddate = datetime.date.today()

            # Get image if uploaded
            image_file = request.FILES.get("image")

            # ---------- Edit Logic ----------
            if gallery_id:
                gallery = session.query(GallerySA).filter(
                    GallerySA.id == gallery_id,
                    GallerySA.status != "Deleted"
                ).first()

                if not gallery:
                    return Response(
                        {"response": "Error", "message": "Gallery item not found"},
                        status=404,
                    )

                # Duplicate title check (exclude self)
                duplicate = session.query(GallerySA).filter(
                    func.lower(GallerySA.title) == title.lower(),
                    GallerySA.id != gallery_id,
                    GallerySA.status != "Deleted"
                ).first()
                if duplicate:
                    return Response(
                        {"response": "Error", "message": "Title already exists"},
                        status=400,
                    )

                # Update fields
                if title:
                    gallery.title = title
                if status:
                    gallery.status = status
                if image_file:
                    compressed_image = self.compress_image(image_file)
                    # Store path or binary depending on your model
                    gallery.image = f"gallery/{compressed_image.name}"
                    # Save to Django media storage
                    # from django.core.files.storage import default_storage
                    default_storage.save(f"gallery/{compressed_image.name}", compressed_image)

                session.commit()
                return Response(
                    {"response": "Success", "message": "Gallery updated successfully"},
                    status=200,
                )

            # Duplicate title check
            duplicate = session.query(GallerySA).filter(
                func.lower(GallerySA.title) == title.lower(),
                GallerySA.status != "Deleted"
            ).first()
            if duplicate:
                return Response(
                    {"response": "Error", "message": "Title already exists"},
                    status=400,
                )

            # Handle image
            image_path = None
            if image_file:
                compressed_image = self.compress_image(image_file)
                image_path = f"gallery/{compressed_image.name}"
                # from django.core.files.storage import default_storage
                default_storage.save(f"gallery/{compressed_image.name}", compressed_image)

            gallery = GallerySA(
                title=title,
                image=image_path,
                status=status,
                createdId=createdId,
                createddate=createddate,
            )
            session.add(gallery)
            session.commit()

            return Response(
                {"response": "Success", "message": "Gallery added successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )
        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )
        finally:
            session.close()

class GetGallery(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch all non-deleted galleries
            galleries = (
                session.query(GallerySA)
                .filter(GallerySA.status != "Deleted")
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

class Active_GetGallery(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetGalleryById(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            gallery_id = data.get("id")
            gallery = session.query(GallerySA).filter(
                GallerySA.id == gallery_id,
                GallerySA.status != "Deleted"
            ).first()

            if not gallery:
                return Response(
                    {"response": "Warning", "message": "Gallery not found"},
                    status=200,
                )

            data = {
                "galleryId": gallery.id,
                "title": gallery.title,
                "image": gallery.image,
                "status": gallery.status,
            }

            return Response(
                {"response": "Success", "data": data},
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

class UpdateGalleryStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            gallery_id = data.get("id")
            status = data.get("status")  

            if not gallery_id or not status:
                return Response(
                    {"response": "Error", "message": "galleryId and status are required"},
                    status=400,
                )

            gallery = session.query(GallerySA).filter(
                GallerySA.id == gallery_id,
                GallerySA.status != "Deleted"
            ).first()

            if not gallery:
                return Response(
                    {"response": "Warning", "message": "Gallery not found"},
                    status=200,
                )

            gallery.status = status
            session.commit()

            return Response(
                {"response": "Success", "message": "Gallery status updated successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class DeleteGallery(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            gallery_id = data.get("id")
            gallery = session.query(GallerySA).filter(
                GallerySA.id == gallery_id,
                GallerySA.status != "Deleted"
            ).first()

            if not gallery:
                return Response(
                    {"response": "Error", "message": "Gallery not found"},
                    status=404,
                )

            gallery.status = "Deleted"
            session.commit()

            return Response(
                {"response": "Success", "message": "Gallery deleted successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class AddEditAboutPage(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def compress_image_webp(self, uploaded_file, quality=70):
        """
        Compress uploaded image and convert to WebP format
        Returns Django ContentFile
        """
        try:
            img = Image.open(uploaded_file)

            # Convert all images to RGB (WebP does not support transparency in all cases)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")

            img_io = BytesIO()
            img.save(img_io, format="WEBP", quality=quality, method=6)
            filename = uploaded_file.name.rsplit(".", 1)[0] + ".webp"
            return ContentFile(img_io.getvalue(), name=filename)

        except Exception as e:
            raise Exception(f"Image conversion to WebP failed: {str(e)}")

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            box_description = data.get("box_description")
            about_id = data.get("id")  # For edit
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = datetime.datetime.now()

            # Prepare section fields
            sec_fields = {}
            for i in range(1, 4):
                sec_fields[f"sec{i}_heading"] = data.get(f"sec{i}_heading")
                sec_fields[f"sec{i}_subheading"] = data.get(f"sec{i}_subheading")

                if f"sec{i}_image" in request.FILES:
                    compressed_image = self.compress_image_webp(request.FILES[f"sec{i}_image"])
                    # Save compressed image to static/uploads/about/section{i}/
                    folder_path = f"uploads/about/section{i}/"
                    os.makedirs(folder_path, exist_ok=True)
                    path = os.path.join(folder_path, compressed_image.name)
                    with open(path, 'wb') as f:
                        f.write(compressed_image.read())
                    sec_fields[f"sec{i}_image"] = path
                else:
                    sec_fields[f"sec{i}_image"] = None

            years_of_experience = int(data.get("years_of_experience", 0))

            # ---------- Edit Logic ----------
            if about_id:
                about = session.query(AboutPageSA).filter(
                    AboutPageSA.id == about_id
                ).first()

                if not about:
                    return Response(
                        {"response": "Error", "message": "About page not found"},
                        status=404,
                    )

                for key, value in sec_fields.items():
                    if value is not None:
                        setattr(about, key, value)
                about.years_of_experience = years_of_experience
                about.status = status
                about.createdId = createdId
                about.createddate = createddate
                about.box_description = box_description

                session.commit()
                session.refresh(about)

                return Response(
                    {"response": "Success", "message": "About page updated successfully"},
                    status=200,
                )

            # ---------- Add Logic ----------
            about = AboutPageSA(
                years_of_experience=years_of_experience,
                status=status,
                createdId=createdId,
                box_description=box_description,
                createddate=createddate,
                **sec_fields
            )
            session.add(about)
            session.commit()
            session.refresh(about)

            return Response(
                {"response": "Success", "message": "About page added successfully", "id": about.id},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class GetAboutPage(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch all non-deleted AboutPage records
            about_list = session.query(AboutPageSA)\
                .filter(AboutPageSA.status != "Deleted")\
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

class Active_GetAboutPage(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetAboutPageById(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            about_id = data.get("id")
            # Query AboutPage by ID
            about = session.query(AboutPageSA).filter(
                AboutPageSA.id == about_id,
                # AboutPageSA.status == "Active" 
            ).first()

            if not about:
                return Response(
                    {"response": "Warning", "message": "About page not found"},
                    status=200,
                )

            data = {
                "id": about.id,
                "box_description": about.box_description,
                "sec1_heading": about.sec1_heading,
                "sec1_subheading": about.sec1_subheading,
                "sec1_image": about.sec1_image,
                "sec2_heading": about.sec2_heading,
                "sec2_subheading": about.sec2_subheading,
                "sec2_image": about.sec2_image,
                "sec3_heading": about.sec3_heading,
                "sec3_subheading": about.sec3_subheading,
                "sec3_image": about.sec3_image,
                "years_of_experience": about.years_of_experience,
                "status": about.status,
                "createdId": about.createdId,
                "createddate": about.createddate,
            }

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


class UpdateAboutPageStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            about_id = data.get("id")
            new_status = data.get("status")

            # Validate input
            if not about_id or not new_status:
                return Response(
                    {"response": "Error", "message": "'id' and 'status' are required"},
                    status=400,
                )

            # Fetch row excluding deleted
            about = session.query(AboutPageSA).filter(
                AboutPageSA.id == about_id,
                func.lower(AboutPageSA.status) != "deleted"
            ).first()

            if not about:
                return Response(
                    {"response": "Error", "message": "About page not found or deleted"},
                    status=404,
                )

            # Update status
            about.status = new_status
            session.commit()
            session.refresh(about)

            return Response(
                {"response": "Success", "message": f"Status updated to '{new_status}' successfully"},
                status=200
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500
            )

        finally:
            session.close()

class DeleteAboutPage(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            about_id = data.get("id")
            # Fetch the AboutPage by ID and not already deleted
            about = session.query(AboutPageSA).filter(
                AboutPageSA.id == about_id,
                AboutPageSA.status != "Deleted"
            ).first()

            if not about:
                return Response(
                    {"response": "Warning", "message": "About page not found or already deleted"},
                    status=200,
                )

            # Soft delete
            about.status = "Deleted"
            session.commit()
            session.refresh(about)

            return Response(
                {"response": "Success", "message": "About page deleted successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class AddEditEstateAddress(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            estate_id = data.get("id") 
            email = data.get("email")
            phone_number = data.get("phone_number")
            address = data.get("address")
            map_location = data.get("map_location")  # Optional
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = data.get("createddate", datetime.datetime.now().strftime("%Y-%m-%d"))

            if not email or not phone_number or not address:
                return Response(
                    {"response": "Error", "message": "Email, phone number, and address are required"},
                    status=400
                )

            # ---------- Edit Logic ----------
            if estate_id:
                estate = session.query(EstateAddressSA).filter(
                    EstateAddressSA.id == estate_id
                ).first()

                if not estate:
                    return Response(
                        {"response": "Warning", "message": "Estate address not found"},
                        status=200
                    )

                estate.email = email
                estate.phone_number = phone_number
                estate.address = address
                if map_location is not None:
                    estate.map_location = map_location
                estate.status = status
                estate.createdId = createdId
                estate.createddate = createddate

                session.commit()
                session.refresh(estate)

                return Response(
                    {"response": "Success", "message": "Estate address updated successfully"},
                    status=200
                )

            # ---------- Add Logic ----------
            estate = EstateAddressSA(
                email=email,
                phone_number=phone_number,
                address=address,
                map_location=map_location,
                status=status,
                createdId=createdId,
                createddate=createddate
            )
            session.add(estate)
            session.commit()
            session.refresh(estate)

            return Response(
                {"response": "Success", "message": "Estate address added successfully", "id": estate.id},
                status=200
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500
            )

        finally:
            session.close()

class GetEstateAddress(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")  

            query = session.query(EstateAddressSA).filter(EstateAddressSA.status != "Deleted")

            if estate_id:  # If ID is provided, filter by it
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

class Active_GetEstateAddress(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")  # Optional: fetch specific address

            query = session.query(EstateAddressSA).filter(EstateAddressSA.status != "Deleted")

            if estate_id:  # If ID is provided, filter by it
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


class GetEstateAddressByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")

            # Warn if ID not provided
            if not estate_id:
                return Response(
                    {"response": "Warning", "message": "Estate address 'id' is required"},
                    status=200
                )

            estate = session.query(EstateAddressSA).filter(
                EstateAddressSA.id == estate_id,
                EstateAddressSA.status != "Deleted"
            ).first()

            if not estate:
                return Response(
                    {"response": "Warning", "message": "No estate address found"},
                    status=200
                )

            data = {
                "id": estate.id,
                "email": estate.email,
                "phone_number": estate.phone_number,
                "address": estate.address,
                "map_location": estate.map_location,
                "status": estate.status,
                "createdId": estate.createdId,
                "createddate": estate.createddate,
            }

            return Response(
                {"response": "Success", "data": data},
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

class UpdateEstateAddressStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")
            new_status = request.data.get("status")

            if not estate_id or not new_status:
                return Response(
                    {"response": "Error", "message": "Both 'id' and 'status' are required"},
                    status=400,
                )

            estate = session.query(EstateAddressSA).filter(EstateAddressSA.id == estate_id).first()

            if not estate:
                return Response(
                    {"response": "Warning", "message": "Estate address not found"},
                    status=200,
                )

            estate.status = new_status
            session.commit()
            session.refresh(estate)

            return Response(
                {"response": "Success", "message": f"Estate address status updated to {new_status}"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()


class DeleteEstateAddress(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            estate_id = request.data.get("id")

            if not estate_id:
                return Response(
                    {"response": "Error", "message": "Estate address 'id' is required"},
                    status=400,
                )

            estate = session.query(EstateAddressSA).filter(
                EstateAddressSA.id == estate_id,
                EstateAddressSA.status != "Deleted"
            ).first()

            if not estate:
                return Response(
                    {"response": "Warning", "message": "Estate address not found or already deleted"},
                    status=200,
                )

            estate.status = "Deleted"
            session.commit()
            session.refresh(estate)

            return Response(
                {"response": "Success", "message": "Estate address deleted successfully"},
                status=200,
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Database error", "errors": str(e)},
                status=500,
            )

        except Exception as e:
            session.rollback()
            return Response(
                {"response": "Error", "message": "Unexpected error", "errors": str(e)},
                status=500,
            )

        finally:
            session.close()

class AddEditGalleryBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            box_id = data.get("id") 
            title = data.get("title", "Gallery")
            description = data.get("description")
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = data.get("createddate", datetime.now().strftime("%Y-%m-%d"))

            if not title:
                return Response(
                    {"response": "Error", "message": "Title is required"},
                    status=400
                )

            # ---------- Edit ----------
            if box_id:
                gallery_box = session.query(GalleryBoxSA).filter(
                    GalleryBoxSA.id == box_id,
                    GalleryBoxSA.status != "Deleted"
                ).first()

                if not gallery_box:
                    return Response(
                        {"response": "Warning", "message": "Gallery box not found"},
                        status=200
                    )

                gallery_box.title = title
                gallery_box.description = description
                gallery_box.status = status
                gallery_box.createdId = createdId
                gallery_box.createddate = createddate

                session.commit()
                session.refresh(gallery_box)

                return Response(
                    {"response": "Success", "message": "Gallery box updated successfully"},
                    status=200
                )

            # ---------- Add ----------
            new_box = GalleryBoxSA(
                title=title,
                description=description,
                status=status,
                createdId=createdId,
                createddate=createddate
            )
            session.add(new_box)
            session.commit()
            session.refresh(new_box)

            return Response(
                {"response": "Success", "message": "Gallery box added successfully", "id": new_box.id},
                status=200
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetGalleryBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(GalleryBoxSA).filter(
                GalleryBoxSA.status != "Deleted"
            ).order_by(GalleryBoxSA.id.desc()).all()

            if not boxes:
                return Response(
                    {"response": "Warning", "message": "No gallery boxes found", "data": []},
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

class Get_ActiveGalleryBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetGalleryBoxByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Warning", "message": "Gallery box 'id' is required"}, status=400)

            box = session.query(GalleryBoxSA).filter(
                GalleryBoxSA.id == box_id,
                GalleryBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response({"response": "Warning", "message": "Gallery box not found"}, status=404)

            data = {
                "id": box.id,
                "title": box.title,
                "description": box.description,
                "status": box.status,
                "createdId": box.createdId,
                "createddate": box.createddate,
            }

            return Response({"response": "Success", "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class UpdateGalleryBoxStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")
            new_status = request.data.get("status")

            if not box_id or not new_status:
                return Response({"response": "Error", "message": "'id' and 'status' are required"}, status=400)

            box = session.query(GalleryBoxSA).filter(GalleryBoxSA.id == box_id).first()

            if not box:
                return Response({"response": "Error", "message": "Gallery box not found"}, status=404)

            box.status = new_status
            session.commit()
            session.refresh(box)

            return Response(
                {"response": "Success", "message": f"Gallery box status updated to {new_status}"},
                status=200
            )

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class DeleteGalleryBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Error", "message": "'id' is required"}, status=400)

            box = session.query(GalleryBoxSA).filter(
                GalleryBoxSA.id == box_id,
                GalleryBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response(
                    {"response": "Error", "message": "Gallery box not found or already deleted"},
                    status=404
                )

            box.status = "Deleted"
            session.commit()
            session.refresh(box)

            return Response({"response": "Success", "message": "Gallery box deleted successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()


class AddEditAboutPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            box_id = data.get("id")  # for edit
            title = data.get("title")
            description = data.get("description")
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = data.get("createddate", datetime.now().strftime("%Y-%m-%d"))

            if not title:
                return Response({"response": "Error", "message": "Title is required"}, status=400)

            # ---------- Edit ----------
            if box_id:
                box = session.query(AboutPageBoxSA).filter(
                    AboutPageBoxSA.id == box_id,
                    AboutPageBoxSA.status != "Deleted"
                ).first()

                if not box:
                    return Response({"response": "Error", "message": "About page box not found"}, status=404)

                box.title = title
                box.description = description
                box.status = status
                box.createdId = createdId
                box.createddate = createddate

                session.commit()
                session.refresh(box)

                return Response({"response": "Success", "message": "About page box updated successfully"}, status=200)

            # ---------- Add ----------
            new_box = AboutPageBoxSA(
                title=title,
                description=description,
                status=status,
                createdId=createdId,
                createddate=createddate
            )
            session.add(new_box)
            session.commit()
            session.refresh(new_box)

            return Response({"response": "Success", "message": "About page box added successfully", "id": new_box.id}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetAboutPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(AboutPageBoxSA).filter(
                AboutPageBoxSA.status != "Deleted"
            ).order_by(AboutPageBoxSA.id.desc()).all()

            if not boxes:
                return Response({"response": "Warning", "message": "No about page boxes found", "count": 0, "data": []}, status=200)

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

class Get_ActiveAboutPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(AboutPageBoxSA).filter(
                AboutPageBoxSA.status == "Active"
            ).order_by(AboutPageBoxSA.id.desc()).all()

            if not boxes:
                return Response({"response": "Warning", "message": "No about page boxes found", "count": 0, "data": []}, status=200)

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

class GetAboutPageBoxByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Warning", "message": "About page box 'id' is required"}, status=400)

            box = session.query(AboutPageBoxSA).filter(
                AboutPageBoxSA.id == box_id,
                AboutPageBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response({"response": "Warning", "message": "About page box not found"}, status=404)

            data = {
                "id": box.id,
                "title": box.title,
                "description": box.description,
                "status": box.status,
                "createdId": box.createdId,
                "createddate": box.createddate,
            }

            return Response({"response": "Success", "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class UpdateAboutPageBoxStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")
            new_status = request.data.get("status")

            if not box_id or not new_status:
                return Response({"response": "Error", "message": "'id' and 'status' are required"}, status=400)

            box = session.query(AboutPageBoxSA).filter(AboutPageBoxSA.id == box_id).first()

            if not box:
                return Response({"response": "Error", "message": "About page box not found"}, status=404)

            box.status = new_status
            session.commit()
            session.refresh(box)

            return Response({"response": "Success", "message": f"About page box status updated to {new_status}"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class DeleteAboutPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Error", "message": "'id' is required"}, status=400)

            box = session.query(AboutPageBoxSA).filter(
                AboutPageBoxSA.id == box_id,
                AboutPageBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response({"response": "Error", "message": "About page box not found or already deleted"}, status=404)

            box.status = "Deleted"
            session.commit()
            session.refresh(box)

            return Response({"response": "Success", "message": "About page box deleted successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()
