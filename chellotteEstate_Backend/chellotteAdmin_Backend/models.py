from django.db import models
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from django.contrib.auth.hashers import make_password,check_password
from sqlalchemy.dialects.mysql import INTEGER, LONGTEXT
# from datetime import datetime
from sqlalchemy import Column, DateTime,Integer,String
# from django.contrib.postgres.fields import JSONField
# from django.utils import timezone
# from sqlalchemy.orm import relationship
Base = declarative_base()
metadata = Base.metadata
# from datetime import date

#----Login------
class superadmintbl(models.Model):
    username = models.CharField(max_length=255, null=True, blank=True)
    password = models.TextField( null=True, blank=True)
    emailId= models.CharField(max_length=250,null=True)
    lastlogined = models.CharField(max_length=50, null=True, blank=True)
    status = models.CharField(max_length=200,null=True) 
    type = models.CharField(max_length=200,null=True) 
    createddate = models.CharField(max_length=200,null=True)
    loginId = models.CharField(max_length=200,null=True)

    class Meta:
        db_table = 'super_admintbl'

class SuperAdminDtl(Base):
    __tablename__ = 'super_admintbl'

    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=True)
    password = Column(Text, nullable=True)
    emailId = Column(String(250), nullable=True)
    lastlogined = Column(String(50), nullable=True)
    status = Column(String(200), nullable=True)
    type = Column(String(200), nullable=True)
    createddate = Column(String(200), nullable=True)
    loginId = Column(String(200), nullable=True)
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)       
    def is_authenticated():
        return True
    
class superadmin_loginhistory(models.Model):
    loginId= models.CharField(max_length=250,null=True)
    logineddate = models.CharField(max_length=50, null=True, blank=True)
    loginedtime = models.CharField(max_length=200,null=True) 
    loginbrowser = models.CharField(max_length=200,null=True) 
    createddate = models.CharField(max_length=200,null=True)

    class Meta:
        db_table = 'super_adminloginhistorytbl'

class SuperAdminLoginHistoryDtl(Base):
    __tablename__ = 'super_adminloginhistorytbl'

    id = Column(Integer, primary_key=True)
    loginId = Column(String(200), nullable=True)
    logineddate = Column(String(50), nullable=True)
    loginedtime = Column(String(200), nullable=True)
    loginbrowser = Column(String(200), nullable=True)
    createddate = Column(String(200), nullable=True)
       
class AuthTokenDtl(models.Model):
    key = models.CharField(max_length=255, null=True, blank=True)
    created = models.CharField(max_length=50, null=True, blank=True)
    loginId = models.CharField(max_length=50, null=True, blank=True)
    fcm_token = models.CharField(max_length=255,null=True, blank=True)

    class Meta:
        db_table = 'auth_token'

class AuthToken(Base):
    __tablename__ = 'auth_token'

    id = Column(INTEGER(11), primary_key=True)
    key = Column(String(255))
    created = Column(DateTime)
    loginId = Column(String(50))
    fcm_token = Column(String(50))
    
#----- Forgot password  ------
class otp(models.Model):
    emailId = models.CharField(max_length=250,null=True)
    otp = models.CharField(max_length=200,null=True) 
    key = models.CharField(max_length=200,null=True) 
    date_time = models.CharField(max_length=200,null=True)
    createddate = models.CharField(max_length=200,null=True)
    status = models.CharField(max_length=200,null=True)

    class Meta:
        db_table =  "otptbl"
        
class OTP(Base):
    __tablename__ = 'otptbl'

    id = Column(INTEGER, primary_key=True)
    emailId = Column(String(250), nullable=True)
    otp = Column(String(200), nullable=True) 
    key = Column(String(200),nullable=True)
    date_time = Column(DateTime) 
    createddate = Column(DateTime) 
    status = Column(String(200),nullable=True)
       
class passwordChangeHistory(models.Model):
    adminId = models.CharField(max_length=250,null=True)
    changeddate = models.CharField(max_length=200,null=True)
    createddate = models.CharField(max_length=200,null=True)
    status = models.CharField(max_length=200,null=True)
    type = models.CharField(max_length=200,null=True) 

    class Meta:
        db_table =  "passwordchangehistorytbl"
      
class PasswordChangeHistory(Base):
    __tablename__ = 'passwordchangehistorytbl'

    id = Column(Integer, primary_key=True)
    adminId = Column(String(250), nullable=True)
    changeddate = Column(DateTime, nullable=True)
    createddate = Column(DateTime, nullable=True)
    status = Column(String(200), nullable=True)
    type = Column(String(200), nullable=True)


#BANNERS
class banner(models.Model):
    bannerId = models.CharField(max_length=250, null=True)
    bannerurl = models.TextField(null=True)  
    title = models.TextField(null=True)     
    description = models.TextField(null=True) 
    status = models.CharField(max_length=250, null=True)
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)

    class Meta:
        db_table = "banner_tbl"
    
class Banner(Base):
    __tablename__ = "banner_tbl"

    id = Column(Integer, primary_key=True)
    bannerId = Column(String(250), nullable=True)
    bannerurl = Column(LONGTEXT, nullable=True)
    title = Column(LONGTEXT, nullable=True)
    description = Column(LONGTEXT, nullable=True)
    status = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)
    createdId = Column(String(250), nullable=True)


class EstateInfo(models.Model):
    title = models.CharField(max_length=255, default="Heritage with a Purpose since 1927")
    # subtitle = models.CharField(max_length=255, default="About the Estate")
    description = models.TextField()
    image_left = models.ImageField(upload_to="estate/", blank=True, null=True)
    image_right = models.ImageField(upload_to="estate/", blank=True, null=True)
    status = models.CharField(max_length=250, null=True)
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)
    class Meta:
        db_table = "estateinfo_tbl"
    def __str__(self):
        return self.title


class TimelineEvent(models.Model):
    # estate = models.ForeignKey(EstateInfo, related_name="timeline", on_delete=models.CASCADE)
    timelineId = models.CharField(max_length=100)   
    year_or_period = models.CharField(max_length=100)  # e.g. "1927", "1950s-60s", "Today"
    title = models.CharField(max_length=255)
    description = models.TextField()
    order = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=250, null=True)
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)
    class Meta:
        db_table = "timeline_tbl"

    def __str__(self):
        return f"{self.year_or_period} - {self.title}"
    
class EstateInfoSA(Base):
    __tablename__ = "estateinfo_tbl"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    image_left = Column(Text, nullable=True)
    image_right = Column(Text, nullable=True)
    status = Column(String(250), nullable=True)
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)


class TimelineEventSA(Base):
    __tablename__ = "timeline_tbl"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timelineId = Column(String(250), nullable=True)   # e.g. "TLN01"
    year_or_period = Column(String(250), nullable=True)
    title = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    order = Column(Integer, nullable=True)
    status = Column(String(250), nullable=True)
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)

class Gallery(models.Model):
    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to="gallery/", blank=True, null=True)
    status = models.CharField(max_length=250, null=True)
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)
    class Meta:
        db_table = "gallery_tbl"

class GallerySA(Base):
    __tablename__ = "gallery_tbl"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    image = Column(String(500), nullable=True)  
    status = Column(String(250), nullable=True)
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)

class AboutPage(models.Model):
    box_description = models.TextField(blank=True, null=True)
    # Section 1
    sec1_heading = models.CharField(max_length=255)
    sec1_subheading = models.TextField(blank=True, null=True)
    sec1_image = models.ImageField(upload_to="about/section1/", blank=True, null=True)

    # Section 2
    sec2_heading = models.CharField(max_length=255)
    sec2_subheading = models.TextField(blank=True, null=True)
    sec2_image = models.ImageField(upload_to="about/section2/", blank=True, null=True)

    # Section 3
    sec3_heading = models.CharField(max_length=255)
    sec3_subheading = models.TextField(blank=True, null=True)
    sec3_image = models.ImageField(upload_to="about/section3/", blank=True, null=True)

    years_of_experience = models.IntegerField()
    status = models.CharField(max_length=250, null=True)
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)
    class Meta:
        db_table = "about_page"


class AboutPageSA(Base):
    __tablename__ = "about_page"

    id = Column(Integer, primary_key=True, autoincrement=True)
    box_description = Column(String(500), nullable=False)
    # Section 1
    sec1_heading = Column(String(255), nullable=False)
    sec1_subheading = Column(String(500), nullable=True)
    sec1_image = Column(String(500), nullable=True)  

    # Section 2
    sec2_heading = Column(String(255), nullable=False)
    sec2_subheading = Column(String(500), nullable=True)
    sec2_image = Column(String(500), nullable=True)

    # Section 3
    sec3_heading = Column(String(255), nullable=False)
    sec3_subheading = Column(String(500), nullable=True)
    sec3_image = Column(String(500), nullable=True)

    years_of_experience = Column(Integer, nullable=False)
    status = Column(String(250), nullable=True)
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)

class EstateAddress(models.Model):
    email = models.EmailField(max_length=255)
    phone_number = models.CharField(max_length=20)
    address = models.TextField()
    map_location = models.CharField(
        max_length=255, 
        help_text="Latitude and Longitude or embed map URL"
    )
    status = models.CharField(max_length=50, default="Active")
    createdId = models.CharField(max_length=100, blank=True, null=True)
    createddate = models.DateField(auto_now_add=True)

    class Meta:
        db_table = "estate_address"

    def __str__(self):
        return f"{self.address} ({self.email})"

class EstateAddressSA(Base):
    __tablename__ = "estate_address"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False)
    phone_number = Column(String(20), nullable=False)
    address = Column(String(500), nullable=False)
    map_location = Column(String(255), nullable=True)  # Lat-long or map URL
    status = Column(String(50), default="Active")
    createdId = Column(String(100), nullable=True)
    createddate = Column(String(250), nullable=True)

class GalleryBox(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default="Active")
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)

    class Meta:
        db_table = "gallery_box"

class GalleryBoxSA(Base):
    __tablename__ = "gallery_box"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=True, default="Active")
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)

class AboutPageBox(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default="Active")
    createdId = models.CharField(max_length=250, null=True)
    createddate = models.CharField(max_length=250, null=True)

    class Meta:
        db_table = "about_page_box"

class AboutPageBoxSA(Base):
    __tablename__ = "about_page_box"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=True, default="Active")
    createdId = Column(String(250), nullable=True)
    createddate = Column(String(250), nullable=True)