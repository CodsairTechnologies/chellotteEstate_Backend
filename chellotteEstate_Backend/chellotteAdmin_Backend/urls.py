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

#GALLERY
    path('api/admin/add_edit_gallery/', views.AddEditGallery.as_view(), name='AddEditGallery'),
    path("api/admin/getGallery/",views.GetGallery.as_view(),name="GetGallery"), 
    path("api/admin/getGallerybyid/",views.GetGalleryById.as_view(),name="GetGalleryById"), 
    path("api/admin/getactiveGallery/",views.Active_GetGallery.as_view(),name="Active_GetGallery"), 
    path("api/admin/UpdateGalleryStatus/",views.UpdateGalleryStatus.as_view(),name="UpdateGalleryStatus"), 
    path("api/admin/deleteGallery/",views.DeleteGallery.as_view(),name="DeleteGallery"), 

#ABOUT
    path('api/admin/AddEditAboutPage/', views.AddEditAboutPage.as_view(), name='AddEditAboutPage'),
    path("api/admin/GetAboutPage/",views.GetAboutPage.as_view(),name="GetAboutPage"), 
    path("api/admin/GetAboutPageById/",views.GetAboutPageById.as_view(),name="GetAboutPageById"), 
    path("api/admin/Active_GetAboutPage/",views.Active_GetAboutPage.as_view(),name="Active_GetAboutPage"), 
    path("api/admin/UpdateAboutPageStatus/",views.UpdateAboutPageStatus.as_view(),name="UpdateAboutPageStatus"), 
    path("api/admin/DeleteAboutPage/",views.DeleteAboutPage.as_view(),name="DeleteAboutPage"), 

#ESTATE ADDRESS
    path('api/admin/AddEditEstateAddress/', views.AddEditEstateAddress.as_view(), name='AddEditEstateAddress'),
    path("api/admin/GetEstateAddress/",views.GetEstateAddress.as_view(),name="GetEstateAddress"), 
    path("api/admin/Active_GetEstateAddress/",views.Active_GetEstateAddress.as_view(),name="Active_GetEstateAddress"), 
    path("api/admin/GetEstateAddressByID/",views.GetEstateAddressByID.as_view(),name="GetEstateAddressByID"), 
    path("api/admin/UpdateEstateAddressStatus/",views.UpdateEstateAddressStatus.as_view(),name="UpdateEstateAddressStatus"), 
    path("api/admin/DeleteEstateAddress/",views.DeleteEstateAddress.as_view(),name="DeleteEstateAddress"), 

#GALLERY PAGE BOX
    path('api/admin/AddEditGalleryBox/', views.AddEditGalleryBox.as_view(), name='AddEditGalleryBox'),
    path("api/admin/GetGalleryBox/",views.GetGalleryBox.as_view(),name="GetGalleryBox"), 
    path("api/admin/Get_ActiveGalleryBox/",views.Get_ActiveGalleryBox.as_view(),name="Get_ActiveGalleryBox"), 
    path("api/admin/GetGalleryBoxByID/",views.GetGalleryBoxByID.as_view(),name="GetGalleryBoxByID"), 
    path("api/admin/UpdateGalleryBoxStatus/",views.UpdateGalleryBoxStatus.as_view(),name="UpdateGalleryBoxStatus"), 
    path("api/admin/DeleteGalleryBox/",views.DeleteGalleryBox.as_view(),name="DeleteGalleryBox"), 

#ABOUT PAGE BOX
    # path('api/admin/AddEditAboutPageBox/', views.AddEditAboutPageBox.as_view(), name='AddEditAboutPageBox'),
    # path("api/admin/GetAboutPageBox/",views.GetAboutPageBox.as_view(),name="GetAboutPageBox"), 
    # path("api/admin/Get_ActiveAboutPageBox/",views.Get_ActiveAboutPageBox.as_view(),name="Get_ActiveAboutPageBox"), 
    # path("api/admin/GetAboutPageBoxByID/",views.GetAboutPageBoxByID.as_view(),name="GetAboutPageBoxByID"), 
    # path("api/admin/UpdateAboutPageBoxStatus/",views.UpdateAboutPageBoxStatus.as_view(),name="UpdateAboutPageBoxStatus"), 
    # path("api/admin/DeleteAboutPageBox/",views.DeleteAboutPageBox.as_view(),name="DeleteAboutPageBox"), 

]