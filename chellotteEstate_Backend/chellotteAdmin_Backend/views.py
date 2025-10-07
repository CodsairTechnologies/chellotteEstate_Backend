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
import io, os
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
        subject = 'Welcome to CHELLOTTE ESTATE'
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

            # image_url = None
            # if image_file and image_file.name != 'undefined':
            #     image = Image.open(image_file)
            #     image_io = BytesIO()

            #     if image.mode in ("RGBA", "P"):
            #         image = image.convert("RGB")

            #     image.save(image_io, format='WEBP', quality=75)
            #     image_io.seek(0)

            #     new_image_name = os.path.splitext(image_file.name)[0] + '.webp'
            #     compressed_image = InMemoryUploadedFile(
            #         image_io, None, new_image_name, 'image/webp', sys.getsizeof(image_io), None
            #     )

            #     # fs = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

            #     fs = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

            #     filename = fs.save(compressed_image.name, compressed_image)
            #     image_url = fs.url(filename)

            image_url = None
            if image_file and image_file.name != 'undefined':
                image = Image.open(image_file)
                image_io = BytesIO()

                # Preserve transparency if present
                if image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

                # Save as WEBP with compression
                image.save(image_io, format='WEBP', quality=75)
                image_io.seek(0)

                new_image_name = os.path.splitext(image_file.name)[0] + '.webp'
                compressed_image = InMemoryUploadedFile(
                    image_io,
                    None,
                    new_image_name,
                    'image/webp',
                    image_io.getbuffer().nbytes,
                    None
                )

                fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, "banners"), base_url=settings.MEDIA_URL + "banners/")
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

    # def compress_image(self, image_file):
    #     """
    #     Compress the uploaded image into WEBP format
    #     """
    #     image = Image.open(image_file)
    #     image_io = BytesIO()

    #     # Convert RGBA/Palette → RGB for WEBP compatibility
    #     if image.mode in ("RGBA", "P"):
    #         image = image.convert("RGB")

    #     # Save compressed version
    #     image.save(image_io, format="WEBP", quality=75)  # adjust quality (50-80) if needed
    #     image_io.seek(0)

    #     # Rename file extension to .webp
    #     new_image_name = os.path.splitext(image_file.name)[0] + ".webp"

    #     return InMemoryUploadedFile(
    #         image_io,
    #         None,
    #         new_image_name,
    #         "image/webp",
    #         sys.getsizeof(image_io),
    #         None,
    #     )
    def compress_image(self, image_file):
        """
        Compress the uploaded image into WEBP format (preserving transparency)
        """
        image = Image.open(image_file)
        image_io = BytesIO()

        # Keep alpha transparency if present
        if image.mode in ("RGBA", "LA", "P"):
            image = image.convert("RGBA")
        else:
            image = image.convert("RGB")

        # Save compressed version
        image.save(image_io, format="WEBP", quality=75)  # adjust quality (50–80) if needed
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
            title = data.get("title", "No Title")
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
                    "Status": e.status,
                    "createdDate": e.createddate
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
                    "Status": e.status,
                    "createdDate": e.createddate
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
                    "response": "warning",
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

    # def compress_image(self, uploaded_file, quality=70):
    #     """
    #     Compress uploaded image, convert to WEBP, and return a ContentFile
    #     """
    #     try:
    #         # Open image with Pillow
    #         img = Image.open(uploaded_file)
    #         img_io = BytesIO()

    #         # Convert images with transparency or palette to RGB
    #         if img.mode in ("RGBA", "P"):
    #             img = img.convert("RGB")

    #         # Save as WEBP (lossy compression for smaller size)
    #         img.save(img_io, format="WEBP", quality=quality, optimize=True)
    #         img_io.seek(0)

    #         # Create a new file name with .webp extension
    #         base_name = uploaded_file.name.rsplit('.', 1)[0]
    #         new_name = f"{base_name}.webp"

    #         return ContentFile(img_io.getvalue(), name=new_name)

    #     except Exception as e:
    #         raise Exception(f"Image compression failed: {str(e)}")
    def compress_image(self, uploaded_file, quality=70):
        """
        Compress uploaded image, convert to WEBP, and return a ContentFile
        """
        try:
            # Open image with Pillow
            img = Image.open(uploaded_file)
            img_io = BytesIO()

            # Preserve transparency when possible
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
            else:
                img = img.convert("RGB")

            # Save as WEBP (lossy compression for smaller size)
            img.save(img_io, format="WEBP", quality=quality, optimize=True)
            img_io.seek(0)

            # Create a new file name with .webp extension
            base_name = uploaded_file.name.rsplit('.', 1)[0]
            new_name = f"{base_name}.webp"

            return ContentFile(img_io.getvalue(), name=new_name)

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

    # def compress_image_webp(self, uploaded_file, quality=70):
    #     """
    #     Compress uploaded image and convert to WebP format
    #     Returns Django ContentFile
    #     """
    #     try:
    #         img = Image.open(uploaded_file)

    #         # Convert all images to RGB (WebP does not support transparency in all cases)
    #         if img.mode in ("RGBA", "P"):
    #             img = img.convert("RGB")

    #         img_io = BytesIO()
    #         img.save(img_io, format="WEBP", quality=quality, method=6)
    #         filename = uploaded_file.name.rsplit(".", 1)[0] + ".webp"
    #         return ContentFile(img_io.getvalue(), name=filename)

    #     except Exception as e:
    #         raise Exception(f"Image conversion to WebP failed: {str(e)}")

    def compress_image_webp(self, uploaded_file, quality=70):
        """
        Compress uploaded image and convert to WebP format
        Returns Django ContentFile
        """
        try:
            img = Image.open(uploaded_file)

            # Preserve transparency (alpha channel) if present
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
            else:
                img = img.convert("RGB")

            img_io = BytesIO()
            # method=6 gives better compression; WebP supports alpha automatically for RGBA
            img.save(img_io, format="WEBP", quality=quality, method=6, optimize=True)
            img_io.seek(0)

            filename = uploaded_file.name.rsplit(".", 1)[0] + ".webp"
            return ContentFile(img_io.getvalue(), name=filename)

        except Exception as e:
            raise Exception(f"Image conversion to WebP failed: {str(e)}")

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            box_description = data.get("box_description")
            box_title = data.get("box_title","About Us")
            about_id = data.get("id")  # For edit
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = datetime.datetime.now()

            # Prepare section fields
            sec_fields = {}
            for i in range(1, 4):
                sec_fields[f"sec{i}_heading"] = data.get(f"sec{i}_heading")
                sec_fields[f"sec{i}_subheading"] = data.get(f"sec{i}_subheading")
                sec_fields[f"sec{i}_description"] = data.get(f"sec{i}_description")

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
                about.box_title = box_title

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
                box_title=box_title,
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
                    "box_title":a.box_title,
                    "box_description":a.box_description,
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
                "box_title": about.box_title,
                "sec1_heading": about.sec1_heading,
                "sec1_subheading": about.sec1_subheading,
                "sec1_description": about.sec1_description,
                "sec1_image": about.sec1_image,
                "sec2_heading": about.sec2_heading,
                "sec2_subheading": about.sec2_subheading,
                "sec2_description": about.sec2_description,
                "sec2_image": about.sec2_image,
                "sec3_heading": about.sec3_heading,
                "sec3_subheading": about.sec3_subheading,
                "sec3_description": about.sec3_description,
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
            createddate = data.get("createddate", datetime.datetime.now().strftime("%Y-%m-%d"))

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


class AddEditProductPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            box_id = data.get("id")  
            title = data.get("title","Products")
            description = data.get("description")
            status = data.get("status", "Active")
            createdId = data.get("createdId", "system")
            createddate = data.get("createddate", datetime.datetime.now().strftime("%Y-%m-%d"))

            if not title:
                return Response({"response": "Error", "message": "Title is required"}, status=400)

            # ---------- Edit ----------
            if box_id:
                box = session.query(ProductPageBoxSA).filter(
                    ProductPageBoxSA.id == box_id,
                    ProductPageBoxSA.status != "Deleted"
                ).first()

                if not box:
                    return Response({"response": "warning", "message": "Product page box not found"}, status=200)

                box.title = title if title else None,
                box.description = description
                box.status = status
                box.createdId = createdId
                box.createddate = createddate

                session.commit()
                session.refresh(box)

                return Response({"response": "Success", "message": "Product page box updated successfully"}, status=200)

            # ---------- Add ----------
            new_box = ProductPageBoxSA(
                title=title if title else None,
                description=description,
                status=status,
                createdId=createdId,
                createddate=createddate
            )
            session.add(new_box)
            session.commit()
            session.refresh(new_box)

            return Response({"response": "Success", "message": "Product page box added successfully", "id": new_box.id}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetProductPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            boxes = session.query(ProductPageBoxSA).filter(
                ProductPageBoxSA.status != "Deleted"
            ).order_by(ProductPageBoxSA.id.desc()).all()

            if not boxes:
                return Response({"response": "Warning", "message": "No product page boxes found", "count": 0, "data": []}, status=200)

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

class Get_ActiveProductPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetProductPageBoxByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Warning", "message": "Product page box 'id' is required"}, status=400)

            box = session.query(ProductPageBoxSA).filter(
                ProductPageBoxSA.id == box_id,
                ProductPageBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response({"response": "Warning", "message": "No data found"}, status=200)

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

class UpdateProductPageBoxStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")
            new_status = request.data.get("status")

            if not box_id or not new_status:
                return Response({"response": "Error", "message": "'id' and 'status' are required"}, status=400)

            box = session.query(ProductPageBoxSA).filter(ProductPageBoxSA.id == box_id).first()

            if not box:
                return Response({"response": "Warning", "message": "No data found"}, status=200)

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

class DeleteProductPageBox(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            box_id = request.data.get("id")

            if not box_id:
                return Response({"response": "Error", "message": "'id' is required"}, status=400)

            box = session.query(ProductPageBoxSA).filter(
                ProductPageBoxSA.id == box_id,
                ProductPageBoxSA.status != "Deleted"
            ).first()

            if not box:
                return Response({"response": "Error", "message": "Product page box not found or already deleted"}, status=404)

            box.status = "Deleted"
            session.commit()
            session.refresh(box)

            return Response({"response": "Success", "message": "Product page box deleted successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()


def compress_image_to_webp(uploaded_image, folder="products", quality=80):
    """Compress an uploaded image, save to /media/<folder>/, and return relative path"""
    if not uploaded_image:
        return None

    try:
        img = Image.open(uploaded_image)

        # Preserve transparency if available
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")

        # Compress and convert to WebP
        buffer = io.BytesIO()
        img.save(buffer, format="WEBP", optimize=True, quality=quality, method=6)
        buffer.seek(0)

        # Create folder if missing
        folder_path = os.path.join(folder)
        os.makedirs(os.path.join("media", folder_path), exist_ok=True)

        # Generate file name
        base_name = os.path.splitext(uploaded_image.name)[0]
        file_name = f"{base_name}.webp"
        file_path = os.path.join(folder_path, file_name).replace("\\", "/")

        # Save file to disk
        default_storage.save(file_path, buffer)

        return file_path  # e.g. "products/icons/myicon.webp"

    except Exception as e:
        print("Image compression error:", e)
        return None

class AddEditProduct(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            product_id = data.get("id")
            productID = data.get("productID")
            title = data.get("title")
            description = data.get("description")
            price = data.get("price")
            availability = data.get("availability")
            brand_name = data.get("brand_name")
            is_featured = data.get("is_featured", False)
            createdId = data.get("createdId", "system")
            createddate = datetime.date.today().strftime("%Y-%m-%d")

            # --- Compress + Save Each Image in Its Folder ---
            cover_image = compress_image_to_webp(request.FILES.get("cover_image"), folder="products/covers")
            background_image = compress_image_to_webp(request.FILES.get("background_image"), folder="products/backgrounds")
            card_icon = compress_image_to_webp(request.FILES.get("card_icon"), folder="products/icons")
            # banner_image = compress_image_to_webp(request.FILES.get("banner_image"), folder="products/banners")

            # -------- EDIT --------
            if product_id:
                product = session.query(ProductSA).filter(
                    ProductSA.id == product_id,
                    ProductSA.status != "Deleted"
                ).first()
                if not product:
                    return Response({"response": "Warning", "message": "Product not found"}, status=200)

                if title:
                    duplicate = session.query(ProductSA).filter(
                        func.lower(ProductSA.title) == func.lower(title),
                        ProductSA.id != product_id,
                        ProductSA.status != "Deleted"
                    ).first()
                    if duplicate:
                        return Response({"response": "Warning", "message": "Duplicate title not allowed"}, status=200)

                product.title = title or product.title
                product.description = description or product.description
                product.price = price or product.price
                product.availability = availability or product.availability
                product.brand_name = brand_name or product.brand_name
                product.is_featured = bool(is_featured)

                if cover_image:
                    product.cover_image = cover_image
                if background_image:
                    product.background_image = background_image
                if card_icon:
                    product.card_icon = card_icon
                # if banner_image:
                #     product.banner_image = banner_image

                session.commit()
                session.refresh(product)
                return Response({"response": "Success", "message": "Product updated successfully"}, status=200)

            # -------- ADD --------
            duplicate = session.query(ProductSA).filter(
                func.lower(ProductSA.title) == func.lower(title),
                ProductSA.status != "Deleted"
            ).first()
            if duplicate:
                return Response({"response": "Warning", "message": "Duplicate product title not allowed"}, status=200)

            new_product = ProductSA(
                productID = productID,
                title=title,
                description=description,
                price=price,
                availability=availability,
                brand_name=brand_name,
                is_featured=bool(is_featured),
                cover_image=cover_image,
                background_image=background_image,
                card_icon=card_icon,
                # banner_image=banner_image,
                status="Active",
                createdId=createdId,
                createddate=createddate,
            )

            session.add(new_product)
            session.commit()
            session.refresh(new_product)
            return Response({"response": "Success", "message": "Product added successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetProducts(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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
                .filter(ProductSA.status != "Deleted")
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

class Get_ActiveProducts(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetProductByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            product_id = request.data.get("id")

            if not product_id:
                return Response({"response": "Error", "message": "Product 'id' is required"}, status=400)

            product = session.query(ProductSA).filter(
                ProductSA.id == product_id,
                ProductSA.status != "Deleted"
            ).first()

            if not product:
                return Response({"response": "Warning", "message": "Product not found"}, status=404)

            data = {
                "id": product.id,
                "productID": product.productID,
                "title": product.title,
                "description": product.description,
                "price": str(product.price) if product.price else None,
                "cover_image": product.cover_image,
                "background_image": product.background_image,
                "card_icon": product.card_icon,
                "is_featured": product.is_featured,
                "availability": product.availability,
                "brand_name": product.brand_name,
                "status": product.status,
                "createdId": product.createdId,
                "createddate": product.createddate,
            }

            return Response({"response": "Success", "data": data}, status=200)

        except SQLAlchemyError as e:
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class UpdateProductStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            product_id = request.data.get("id")
            new_status = request.data.get("status")

            if not product_id or not new_status:
                return Response({"response": "Error", "message": "'id' and 'status' are required"}, status=400)

            product = session.query(ProductSA).filter(ProductSA.id == product_id).first()

            if not product:
                return Response({"response": "Error", "message": "Product not found"}, status=404)

            product.status = new_status
            session.commit()
            session.refresh(product)

            return Response(
                {"response": "Success", "message": f"Product status updated to {new_status}"},
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

class DeleteProduct(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            product_id = request.data.get("id")

            if not product_id:
                return Response({"response": "Error", "message": "'id' is required"}, status=400)

            product = session.query(ProductSA).filter(
                ProductSA.id == product_id,
                ProductSA.status != "Deleted"
            ).first()

            if not product:
                return Response({"response": "Error", "message": "Product not found or already deleted"}, status=404)

            product.status = "Deleted"
            session.commit()
            session.refresh(product)

            return Response({"response": "Success", "message": "Product deleted successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class AddEditTestimonial(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    # def compress_image(self, image_file, upload_path):
    #     try:
    #         img = Image.open(image_file)
    #         img_io = io.BytesIO()
    #         img.save(img_io, format="WEBP", quality=70)
    #         file_name = f"{upload_path}/{image_file.name.split('.')[0]}.webp"
    #         path = default_storage.save(file_name, img_io)
    #         return "/" + path
    #     except Exception:
    #         return None
    def compress_image(self, image_file, upload_path):
        try:
            img = Image.open(image_file)

            # Preserve transparency if available
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
            else:
                img = img.convert("RGB")

            img_io = io.BytesIO()
            img.save(img_io, format="WEBP", quality=70, method=6)
            img_io.seek(0)

            file_name = f"{upload_path}/{os.path.splitext(image_file.name)[0]}.webp"

            # Save properly using default_storage
            path = default_storage.save(file_name, ContentFile(img_io.getvalue()))
            return "/" + path

        except Exception as e:
            print("Image compression error:", e)
            return None

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            testimonial_id = data.get("id")  # for edit
            name = data.get("name")
            testimony = data.get("testimony")
            profile_image = request.FILES.get("profile_image")
            createdId = data.get("createdId")

            # ---------- Edit ----------
            if testimonial_id:
                testimonial = session.query(TestimonialSA).filter(
                    TestimonialSA.id == testimonial_id,
                    TestimonialSA.status != "Deleted"
                ).first()

                if not testimonial:
                    return Response({"response": "Error", "message": "Testimonial not found"}, status=404)

                if name:
                    testimonial.name = name
                if testimony:
                    testimonial.testimony = testimony
                if profile_image:
                    testimonial.profile_image = self.compress_image(profile_image, "uploads/testimonials")

                session.commit()
                return Response({"response": "Success", "message": "Testimonial updated successfully"}, status=200)

            # ---------- Duplicate check ----------
            duplicate = session.query(TestimonialSA).filter(
                TestimonialSA.name == name,
                TestimonialSA.testimony == testimony,
                TestimonialSA.status != "Deleted"
            ).first()

            if duplicate:
                return Response({"response": "Error", "message": "Duplicate testimonial exists"}, status=400)

            # ---------- Add ----------
            profile_img_path = None
            if profile_image:
                profile_img_path = self.compress_image(profile_image, "uploads/testimonials")

            new_testimonial = TestimonialSA(
                name=name,
                testimony=testimony,
                profile_image=profile_img_path,
                status="Active",
                createdId=createdId,
                createddate=datetime.date.today()
            )
            session.add(new_testimonial)
            session.commit()

            return Response({"response": "Success", "message": "Testimonial added successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)

        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

class GetTestimonials(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            testimonials = session.query(TestimonialSA).filter(
                TestimonialSA.status != "Deleted"
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

class Get_ActiveTestimonials(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetTestimonialByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            testimonial_id = request.data.get("id")

            if not testimonial_id:
                return Response({"response": "Warning", "message": "ID is required"}, status=400)

            testimonial = session.query(TestimonialSA).filter(
                TestimonialSA.id == testimonial_id,
                TestimonialSA.status != "Deleted"
            ).first()

            if not testimonial:
                return Response({"response": "Warning", "message": "Testimonial not found"}, status=200)

            data = {
                "id": testimonial.id,
                "name": testimonial.name,
                "testimony": testimonial.testimony,
                "profile_image": testimonial.profile_image,
                "status": testimonial.status,
                "createdId": testimonial.createdId,
                "createddate": str(testimonial.createddate)
            }

            return Response({"response": "Success", "data": data}, status=200)

        except Exception as e:
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

class UpdateTestimonialStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            testimonial_id = request.data.get("id")
            status = request.data.get("status")  # Active / Inactive / Deleted

            if not testimonial_id or not status:
                return Response({"response": "Warning", "message": "ID and status are required"}, status=400)

            testimonial = session.query(TestimonialSA).filter(TestimonialSA.id == testimonial_id).first()
            if not testimonial:
                return Response({"response": "Error", "message": "Testimonial not found"}, status=404)

            testimonial.status = status
            session.commit()

            return Response({"response": "Success", "message": "Status updated successfully"}, status=200)

        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

class DeleteTestimonial(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            testimonial_id = request.data.get("id")

            if not testimonial_id:
                return Response({"response": "Warning", "message": "ID is required"}, status=400)

            testimonial = session.query(TestimonialSA).filter(TestimonialSA.id == testimonial_id).first()
            if not testimonial:
                return Response({"response": "Error", "message": "Testimonial not found"}, status=404)

            testimonial.status = "Deleted"
            session.commit()

            return Response({"response": "Success", "message": "Testimonial deleted successfully"}, status=200)

        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

class AddEditPlantation(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def compress_image(self, image_file, quality=70):
        """
        Compress and convert uploaded image to WEBP, save to /media/home_plantation/,
        and return its relative path.
        """
        try:
            img = Image.open(image_file)
            img_io = io.BytesIO()

            # Preserve transparency when available
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
            else:
                img = img.convert("RGB")

            #  Save as WebP (supports transparency)
            img.save(img_io, format="WEBP", optimize=True, quality=quality, method=6)
            img_io.seek(0)

            # Unique file name
            file_name = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{os.path.splitext(image_file.name)[0]}.webp"
            relative_path = f"home_plantation/{file_name}"

            # Save using Django’s default storage
            default_storage.save(relative_path, ContentFile(img_io.getvalue()))

            return relative_path.replace("\\", "/")

        except Exception as e:
            raise Exception(f"Image compression failed: {str(e)}")

    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data

            highlight_id = data.get("id")  # For edit
            section_title = data.get("section_title", "Shade-Grown Coffee & Orthodox Tea from Wayanad")
            title = data.get("title")
            description = data.get("description")
            order = data.get("order")
            status = data.get("status", "Active")
            createdId = data.get("createdId")

            image1 = request.FILES.get("image1")
            image2 = request.FILES.get("image2")
            image3 = request.FILES.get("image3")

            # ---------- EDIT ----------
            if highlight_id:
                highlight = session.query(HomePlantationSA).filter(
                    HomePlantationSA.id == highlight_id,
                    HomePlantationSA.status != "Deleted"
                ).first()

                if not highlight:
                    return Response({"response": "Warning", "message": "Home Plantation not found"}, status=200)

                highlight.section_title = section_title or highlight.section_title
                highlight.title = title or highlight.title
                highlight.description = description or highlight.description
                highlight.order = order or highlight.order
                highlight.status = status or highlight.status

                if image1:
                    highlight.image1 = self.compress_image(image1)
                if image2:
                    highlight.image2 = self.compress_image(image2)
                if image3:
                    highlight.image3 = self.compress_image(image3)

                session.commit()
                session.refresh(highlight)

                return Response({"response": "Success", "message": "Home Plantation updated successfully"}, status=200)

            # ---------- ADD ----------
            if not order:
                max_order = session.query(func.max(HomePlantationSA.order)).scalar() or 0
                order = max_order + 1

            new_highlight = HomePlantationSA(
                section_title=section_title,
                title=title,
                description=description,
                order=order,
                status=status,
                createdId=createdId,
                createddate=datetime.date.today(),
                image1=self.compress_image(image1) if image1 else None,
                image2=self.compress_image(image2) if image2 else None,
                image3=self.compress_image(image3) if image3 else None,
            )

            session.add(new_highlight)
            session.commit()
            session.refresh(new_highlight)

            return Response({"response": "Success", "message": "Home plantation added successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)

        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)

        finally:
            session.close()

class GetHomePlantations(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            # Fetch all active highlights
            highlights = (
                session.query(HomePlantationSA)
                .filter(HomePlantationSA.status != "Deleted")
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

class Get_ActiveHomePlantations(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

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

class GetHomePlantationByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            highlight_id = request.data.get("id")

            if not highlight_id:
                return Response(
                    {"response": "Warning", "message": "Plantation ID is required"},
                    status=200
                )

            highlight = (
                session.query(HomePlantationSA)
                .filter(HomePlantationSA.id == highlight_id, HomePlantationSA.status != "Deleted")
                .first()
            )

            if not highlight:
                return Response(
                    {"response": "Warning", "message": "No Plantation found for the given ID"},
                    status=200
                )

            data = {
                "id": highlight.id,
                "section_title": highlight.section_title,
                "title": highlight.title,
                "description": highlight.description,
                "image1": highlight.image1,
                "image2": highlight.image2,
                "image3": highlight.image3,
                "order": highlight.order,
                "status": highlight.status,
                "createdId": highlight.createdId,
                "createddate": highlight.createddate,
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

class UpdateHomePlantationStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            highlight_id = request.data.get("id")
            status = request.data.get("status")

            if not highlight_id or not status:
                return Response(
                    {"response": "Warning", "message": "ID and status are required"},
                    status=400
                )

            highlight = (
                session.query(HomePlantationSA)
                .filter(HomePlantationSA.id == highlight_id, HomePlantationSA.status != "Deleted")
                .first()
            )

            if not highlight:
                return Response(
                    {"response": "Warning", "message": "No plantation found for given ID"},
                    status=200
                )

            highlight.status = status
            session.commit()
            session.refresh(highlight)

            return Response(
                {"response": "Success", "message": "Status updated successfully"},
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

class DeleteHomePlantation(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            highlight_id = request.data.get("id")

            if not highlight_id:
                return Response(
                    {"response": "Warning", "message": "Plantation ID is required"},
                    status=400
                )

            highlight = (
                session.query(HomePlantationSA)
                .filter(HomePlantationSA.id == highlight_id, HomePlantationSA.status != "Deleted")
                .first()
            )

            if not highlight:
                return Response(
                    {"response": "Warning", "message": "No plantation found for given ID"},
                    status=404
                )

            highlight.status = "Deleted"
            session.commit()

            return Response(
                {"response": "Success", "message": "Plantation deleted successfully"},
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

class AddEditTourismCard(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def compress_image(self, image_file):
        """Compress and save uploaded image as WEBP inside /media/uploads/tourism/cards/"""
        if not image_file:
            return None
        try:
            image = Image.open(image_file)

            # Preserve transparency if present
            if image.mode in ("RGBA", "LA", "P"):
                image = image.convert("RGBA")
            else:
                image = image.convert("RGB")

            img_io = io.BytesIO()
            # Save with transparency if available
            image.save(img_io, format="WEBP", optimize=True, quality=70, method=6)
            img_io.seek(0)

            # Generate file name and save path
            file_name = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.webp"
            folder_path = os.path.join(settings.MEDIA_ROOT, "uploads", "tourism", "cards")

            # Ensure directory exists
            os.makedirs(folder_path, exist_ok=True)

            # Save using Django FileSystemStorage
            fs = FileSystemStorage(location=folder_path, base_url=settings.MEDIA_URL + "uploads/tourism/cards/")
            saved_name = fs.save(file_name, ContentFile(img_io.getvalue()))
            file_url = fs.url(saved_name)

            return file_url.replace("\\", "/")

        except Exception as e:
            print("Image compression failed:", e)
            return None


    def post(self, request):
        session = dbsession.Session()
        try:
            data = request.data
            card_id = data.get("id")  # For edit
            card_title = data.get("card_title")
            card_description = data.get("card_description")
            card_image = request.FILES.get("card_image")
            status = data.get("status", "Active")
            createdId = data.get("createdId")

            # Validation
            if not card_title:
                return Response({"response": "Warning", "message": "Card title is required"}, status=200)

            # ---------- Edit ----------
            if card_id:
                card = session.query(TourismCardSA).filter(
                    TourismCardSA.id == card_id,
                    TourismCardSA.status != "Deleted"
                ).first()
                if not card:
                    return Response({"response": "Warning", "message": "Tourism card not found"}, status=404)

                # Duplicate check
                duplicate = session.query(TourismCardSA).filter(
                    TourismCardSA.card_title == card_title,
                    TourismCardSA.id != card_id,
                    TourismCardSA.status != "Deleted"
                ).first()
                if duplicate:
                    return Response({"response": "Warning", "message": "Card title already exists"}, status=200)

                card.card_title = card_title
                card.card_description = card_description if card_description else card.card_description
                card.status = status
                if card_image:
                    card.card_image = self.compress_image(card_image)

                session.commit()
                session.refresh(card)
                return Response({"response": "Success", "message": "Tourism card updated successfully"}, status=200)

            # ---------- Add ----------
            # Check total count (maximum 4 cards)
            # total_cards = session.query(func.count(TourismCardSA.id)).filter(TourismCardSA.status == "Active").scalar()
            # if total_cards >= 4:
            #     return Response({"response": "Warning", "message": "Only 4 tourism cards can be showcased"}, status=200)

            # Duplicate check
            duplicate = session.query(TourismCardSA).filter(
                TourismCardSA.card_title == card_title,
                TourismCardSA.status != "Deleted"
            ).first()
            if duplicate:
                return Response({"response": "Warning", "message": "Card title already exists"}, status=200)

            new_card = TourismCardSA(
                card_title=card_title,
                card_description=card_description,
                card_image=self.compress_image(card_image) if card_image else None,
                status=status,
                createdId=createdId,
                createddate=datetime.date.today()
            )
            session.add(new_card)
            session.commit()
            session.refresh(new_card)
            return Response({"response": "Success", "message": "Tourism card added successfully"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class GetTourismCards(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            cards = session.query(TourismCardSA).filter(
                TourismCardSA.status != "Deleted"
            ).order_by(TourismCardSA.id.asc()).all()

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


class Get_ActiveTourismCards(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            cards = session.query(TourismCardSA).filter(
                TourismCardSA.status == "Active"
            ).order_by(TourismCardSA.id.asc()).all()

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


class GetTourismCardByID(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            card_id = request.data.get("id")
            if not card_id:
                return Response({"response": "Warning", "message": "Card ID is required"}, status=400)

            card = session.query(TourismCardSA).filter(
                TourismCardSA.id == card_id, TourismCardSA.status != "Deleted"
            ).first()
            if not card:
                return Response({"response": "Warning", "message": "Tourism card not found"}, status=404)

            data = {
                "id": card.id,
                "card_title": card.card_title,
                "card_description": card.card_description,
                "card_image": card.card_image,
                "status": card.status,
                "createdId": card.createdId,
                "createddate": str(card.createddate)
            }
            return Response({"response": "Success", "data": data}, status=200)
        finally:
            session.close()


class UpdateTourismCardStatus(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            card_id = request.data.get("id")
            status = request.data.get("status")
            if not card_id or not status:
                return Response({"response": "Warning", "message": "ID and status are required"}, status=400)

            card = session.query(TourismCardSA).filter(
                TourismCardSA.id == card_id, TourismCardSA.status != "Deleted"
            ).first()
            if not card:
                return Response({"response": "Warning", "message": "Tourism card not found"}, status=404)

            card.status = status
            session.commit()
            session.refresh(card)
            return Response({"response": "Success", "message": "Status updated successfully"}, status=200)
        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

class DeleteTourismCard(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            card_id = request.data.get("id")
            if not card_id:
                return Response({"response": "Warning", "message": "Card ID is required"}, status=400)

            card = session.query(TourismCardSA).filter(
                TourismCardSA.id == card_id, TourismCardSA.status != "Deleted"
            ).first()
            if not card:
                return Response({"response": "Warning", "message": "Tourism card not found"}, status=404)

            card.status = "Deleted"
            session.commit()
            return Response({"response": "Success", "message": "Tourism card deleted successfully"}, status=200)
        except SQLAlchemyError as e:
            session.rollback()
            return Response({"response": "Error", "message": "Database error", "errors": str(e)}, status=500)
        except Exception as e:
            session.rollback()
            return Response({"response": "Error", "message": "Unexpected error", "errors": str(e)}, status=500)
        finally:
            session.close()

    
#------Contact Enquiry----------
class GetEnquiry(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            sql = '''
                SELECT 
                    id,
                    name,
                    email,
                    phoneNumber,
                    message,
                    DATE(created_date) AS enquiry_date,
                    status
                FROM customer_enquiry_tbl
                ORDER BY created_date DESC
            '''
            result = session.execute(text(sql))
            adminObjs = [dict(row) for row in result.mappings()]

            if adminObjs:
                return Response({"response": "Success", "enquiry": adminObjs}, status=200)
            else:
                return Response({'response': 'Warning', 'message': "No data found"}, status=200)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'Error',
                'message': 'Database error occurred',
                'Error': str(e)
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
        
#SETTINGS
class UpdateAdminUsernameAndEmail(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()
        try:
            admin_id = request.data.get("id")
            if not admin_id:
                return Response({
                    "response": "error",
                    "message": "Admin ID is required."
                }, status=status.HTTP_400_BAD_REQUEST)

            admin = session.query(SuperAdminDtl).filter_by(id=admin_id).first()
            if not admin:
                return Response({
                    "response": "error",
                    "message": "Admin not found."
                }, status=status.HTTP_404_NOT_FOUND)
            
            new_username = request.data.get("username", admin.username)
            new_email = request.data.get("emailId", admin.emailId)

            admin.username = new_username
            admin.emailId = new_email
            session.commit()

            return Response({
                "response": "success",
                "message": "Admin username and email updated successfully.",
                "data": {
                    "id": admin.id,
                    "username": admin.username,
                    "emailId": admin.emailId
                }
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Database error occurred.",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
           session.close()
           
           
class ProfileChangePassword(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        session = dbsession.Session()

        try:
            email = request.data.get('email')
            old_password = request.data.get('old_password')
            new_password = request.data.get('new_password')
            confirm_password = request.data.get('confirm_password')

            # Validate required fields
            if not all([email, old_password, new_password, confirm_password]):
                return Response({'response': 'Error', 'message': 'All fields are required'}, status=status.HTTP_200_OK)

            # Fetch admin by email
            admin = session.query(SuperAdminDtl).filter(SuperAdminDtl.emailId == email).one_or_none()

            if not admin:
                return Response({'response': 'Error', 'message': 'Admin not found'}, status=status.HTTP_200_OK)


            # Check old password
            if not check_password(old_password, admin.password):
                return Response({'response': 'Error', 'message': 'Old password is incorrect'}, status=status.HTTP_200_OK)

            # Check new/confirm password match
            if new_password != confirm_password:
                return Response({'response': 'Error', 'message': 'New password and confirm password do not match'}, status=status.HTTP_200_OK)

            # Prevent same old and new password
            if check_password(new_password, admin.password):
                return Response({'response': 'Error', 'message': 'New password cannot be same as the old password'}, status=status.HTTP_200_OK)

            # Update password
            admin.password = make_password(new_password)
            session.add(admin)

            # Add password history
            password_obj = PasswordChangeHistory()
            password_obj.status = 'Active'
            password_obj.changeddate = datetime.datetime.now()
            password_obj.loginId = admin.loginId
            password_obj.createddate = datetime.datetime.now()
            password_obj.type = admin.type
            session.add(password_obj)

            session.commit()
            return Response({'response': 'Success', 'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Database error. Please try again later.', 'error': str(e)}, status=status.HTTP_200_OK)

        except Exception as e:
            session.rollback()
            return Response({'response': 'Error', 'message': 'Something went wrong. Please try again later.', 'error': str(e)}, status=status.HTTP_200_OK)

        finally:
            session.close()