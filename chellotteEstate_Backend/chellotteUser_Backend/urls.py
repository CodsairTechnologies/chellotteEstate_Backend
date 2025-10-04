from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
#LOGIN   
 

#GET BANNERS
    path("api/user/gethomebanner/",views.UserGetActiveBanner.as_view(),name="getactivebanner"), 

#GET HOME ABOUT
    path("api/user/User_GetEstateWithTimeline/",views.User_GetEstateWithTimeline.as_view(),name="User_GetEstateWithTimeline"), 

#GET HOME GALLERY
    path("api/user/home_GetGallery/",views.home_GetGallery.as_view(),name="home_GetGallery"), 

#ESTATE ADDRESS
    path("api/user/home_GetEstateAddress/",views.GetEstateAddress.as_view(),name="Active_GetEstateAddress"), 

#GALLERY PAGE
    path("api/user/User_GalleryPage/",views.User_GalleryPage.as_view(),name="User_GalleryPage"), 
    path("api/user/FilterGalleryByName/",views.FilterGalleryByName.as_view(),name="FilterGalleryByName"),
    path("api/user/GalleryBox/",views.GalleryBox.as_view(),name="GalleryBox"),

#ABOUT PAGE
    path("api/user/GetAboutPage/",views.GetAboutPage.as_view(),name="GetAboutPage"), 


]
