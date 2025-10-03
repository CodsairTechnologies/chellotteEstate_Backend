from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
    
#LOGIN    
    path('api/admin/login/', views.SuperAdminAuthentication, name='superadminlogin'),
    path("api/admin/getprofile/",views.GetProfile.as_view(),name="getprofile"), 

# FORGET PASSWORD
    path('api/admin/forgotpassword/', views.AdminforgotPassword, name='forgotpassword'),
    path("api/admin/verifyotp/",views.AdminverifyOtp,name="verifyotp"), 
    path("api/admin/changepassword/",views.AdminchangePassword,name="changepassword"), 

#BANNERS
    path('api/admin/add_editbanner/', views.AddEditBanner.as_view(), name='addbanner'),
    path("api/admin/getbanner/",views.GetBanner.as_view(),name="getbanner"), 
    path("api/admin/getbannerbyid/",views. GetBannerById.as_view(),name="getbannerbyid"), 
    path("api/admin/getactivebanner/",views.GetActiveBanner.as_view(),name="getactivebanner"), 
    path("api/admin/updatebannerstatus/",views.UpdateBannerStatus.as_view(),name="updatebannerstatus"), 
    path("api/admin/deletebanner/",views.DeleteBanner.as_view(),name="updatebannerstatus"), 

#ESTATE
    path('api/admin/add_edit_estate/', views.AddEditEstate.as_view(), name='add_edit_estate'),
    path("api/admin/getEstate/",views.GetEstate.as_view(),name="getEstate"), 
    path("api/admin/getEstatebyid/",views.GetEstateById.as_view(),name="getEstatebyid"), 
    path("api/admin/getactiveEstate/",views.Active_GetEstate.as_view(),name="getactiveEstate"), 
    path("api/admin/updateEstatestatus/",views.UpdateEstateStatus.as_view(),name="updateEstatestatus"), 
    path("api/admin/deleteEstate/",views.DeleteEstate.as_view(),name="deleteEstate"), 

#TIMELINE
    path('api/admin/add_edit_Timeline/', views.AddEditTimeline.as_view(), name='add_edit_Timeline'),
    path("api/admin/getTimeline/",views.GetTimeline.as_view(),name="getTimeline"), 
    path("api/admin/getTimelinebyid/",views.GetTimelineById.as_view(),name="getTimelinebyid"), 
    path("api/admin/getactiveTimeline/",views.Active_GetTimeline.as_view(),name="getactiveTimeline"), 
    path("api/admin/updateTimelinestatus/",views.UpdateTimelineStatus.as_view(),name="updateTimelinestatus"), 
    path("api/admin/deleteTimeline/",views.DeleteTimeline.as_view(),name="deleteTimeline"), 

]