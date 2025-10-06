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

#TESTIMONIALS 
    path('api/user/Get_ActiveTestimonials/', views.Get_Testimonials.as_view(), name='Get_ActiveTestimonials'),

#FEATURED PRODUCTS 
    path('api/user/GetFeaturedProducts/', views.GetFeaturedProducts.as_view(), name='GetFeaturedProducts'),

#ESTATE ADDRESS
    path("api/user/home_GetEstateAddress/",views.GetEstateAddress.as_view(),name="Active_GetEstateAddress"), 

#GALLERY PAGE
    path("api/user/User_GalleryPage/",views.User_GalleryPage.as_view(),name="User_GalleryPage"), 
    path("api/user/FilterGalleryByName/",views.FilterGalleryByName.as_view(),name="FilterGalleryByName"),
    path("api/user/GalleryBox/",views.GalleryBox.as_view(),name="GalleryBox"),

#ABOUT PAGE
    path("api/user/GetAboutPage/",views.GetAboutPage.as_view(),name="GetAboutPage"), 

##PRODUCT PAGE 
    path('api/user/Get_Products/', views.Get_Products.as_view(), name='Get_Products'),
    path('api/user/FilterProducts/', views.FilterProducts.as_view(), name='FilterProducts'),
    path('api/user/SearchProducts/', views.SearchProducts.as_view(), name='SearchProducts'),
    path('api/user/Get_ProductPageBox/', views.Get_ProductPageBox.as_view(), name='Get_ProductPageBox'),

#ENQUIRY
    path('api/user/add_contactenquiry/', views.AddCustomerEnquiry.as_view(), name='addcontactenquiry'),

#HOME PLANTATIONS 
    path("api/user/GetHomePlantations/",views.GetHomePlantations.as_view(),name="GetHomePlantations"), 

#HOME TOURISM CARDS 
    path("api/user/GetTourismCards/",views.GetTourismCards.as_view(),name="GetTourismCards"), 

]
