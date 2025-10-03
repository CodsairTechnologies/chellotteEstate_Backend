import jwt
import json
import datetime
from django.conf import settings
from chellotteAdmin_Backend.models import AuthToken,SuperAdminDtl
from django.http import HttpResponse
from chellotteEstate_Backend import dbsession
from sqlalchemy.exc import SQLAlchemyError
from rest_framework import status, exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from datetime import date
from sqlalchemy.orm.exc import NoResultFound 
import logging
logger = logging.getLogger(__name__)

class TokenAuthentication(BaseAuthentication):

    def get_model(self):
        return SuperAdminDtl

    def authenticate(self, request):
        session = dbsession.Session()
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header'
            raise exceptions.AuthenticationFailed(msg)
        
        try:
            token = auth[1].decode('utf-8')
            if token == "null":
                msg = 'Null token not allowed'
                raise exceptions.AuthenticationFailed(msg)
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token, session)

    def authenticate_credentials(self, token, session):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            msg = {'response': 'Error', 'message': "Token is expired", 'status': "401"}
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            session.rollback()
            msg = {'response': 'Error', 'message': "Token mismatch"}
            raise exceptions.AuthenticationFailed(msg)
        
        loginId = payload.get('loginId')
        expiry = payload.get('expiry')

        if not loginId or not expiry:
            raise exceptions.AuthenticationFailed({'response': 'Error', 'message': 'Invalid token payload'})

        try:
            user = session.query(SuperAdminDtl).filter_by(loginId=loginId).one()
            auth_token = session.query(AuthToken).filter_by(loginId=loginId, key=token).one()

            if auth_token.key != token:
                raise exceptions.AuthenticationFailed({'response': 'Error', 'message': "Token mismatch", 'status': "401"})

            
            if datetime.datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S") < datetime.datetime.now():
                self.logout(loginId, token, session) 
                raise exceptions.AuthenticationFailed({'response': 'Error', 'message': 'Token Expired.'})
        except NoResultFound:
            session.rollback()
            raise exceptions.AuthenticationFailed({'response': 'Error', 'message': "Invalid token"})
        except SQLAlchemyError:
            session.rollback()
            raise exceptions.AuthenticationFailed({'response': 'Error', 'message': "Internal server error"})

        session.close()
        return (user, token)

    def authenticate_header(self, request):
        return 'Bearer'

    def logout(self, loginId, token, session):
        try:
            logger.info(f"Logging out user with loginId={loginId} and token={token}")
            session.query(AuthToken).filter_by(loginId=loginId, key=token).delete()
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            logger.error(f"Failed to logout user with loginId={loginId} and token={token}")
            raise exceptions.AuthenticationFailed({'response': 'Error', 'message': 'Failed to logout user'}, status=500)
        finally:
            session.close()    