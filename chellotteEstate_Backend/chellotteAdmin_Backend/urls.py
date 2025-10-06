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

#PRODUCT PAGE BOX
    path('api/admin/AddEditProductPageBox/', views.AddEditProductPageBox.as_view(), name='AddEditProductPageBox'),
    path("api/admin/GetProductPageBox/",views.GetProductPageBox.as_view(),name="GetProductPageBox"), 
    path("api/admin/Get_ActiveProductPageBox/",views.Get_ActiveProductPageBox.as_view(),name="Get_ActiveProductPageBox"), 
    path("api/admin/GetProductPageBoxByID/",views.GetProductPageBoxByID.as_view(),name="GetProductPageBoxByID"), 
    path("api/admin/UpdateProductPageBoxStatus/",views.UpdateProductPageBoxStatus.as_view(),name="UpdateProductPageBoxStatus"), 
    path("api/admin/DeleteProductPageBox/",views.DeleteProductPageBox.as_view(),name="DeleteProductPageBox"), 

#PRODUCT 
    path('api/admin/AddEditProduct/', views.AddEditProduct.as_view(), name='AddEditProduct'),
    path("api/admin/GetProducts/",views.GetProducts.as_view(),name="GetProducts"), 
    path("api/admin/Get_ActiveProducts/",views.Get_ActiveProducts.as_view(),name="Get_ActiveProducts"), 
    path("api/admin/GetProductByID/",views.GetProductByID.as_view(),name="GetProductByID"), 
    path("api/admin/UpdateProductStatus/",views.UpdateProductStatus.as_view(),name="UpdateProductStatus"), 
    path("api/admin/DeleteProduct/",views.DeleteProduct.as_view(),name="DeleteProduct"), 

#TESTIMONIALS 
    path('api/admin/AddEditTestimonial/', views.AddEditTestimonial.as_view(), name='AddEditTestimonial'),
    path("api/admin/GetTestimonials/",views.GetTestimonials.as_view(),name="GetTestimonials"), 
    path("api/admin/Get_ActiveTestimonials/",views.Get_ActiveTestimonials.as_view(),name="Get_ActiveTestimonials"), 
    path("api/admin/GetTestimonialByID/",views.GetTestimonialByID.as_view(),name="GetTestimonialByID"), 
    path("api/admin/UpdateTestimonialStatus/",views.UpdateTestimonialStatus.as_view(),name="UpdateTestimonialStatus"), 
    path("api/admin/DeleteTestimonial/",views.DeleteTestimonial.as_view(),name="DeleteTestimonial"), 

#HOME TOURISM CARDS 
    path('api/admin/AddEditTourismCard/', views.AddEditTourismCard.as_view(), name='AddEditTourismCard'),
    path("api/admin/GetTourismCards/",views.GetTourismCards.as_view(),name="GetTourismCards"), 
    path("api/admin/Get_ActiveTourismCards/",views.Get_ActiveTourismCards.as_view(),name="Get_ActiveTourismCards"), 
    path("api/admin/GetTourismCardByID/",views.GetTourismCardByID.as_view(),name="GetTourismCardByID"), 
    path("api/admin/UpdateTourismCardStatus/",views.UpdateTourismCardStatus.as_view(),name="UpdateTourismCardStatus"), 
    path("api/admin/DeleteTourismCard/",views.DeleteTourismCard.as_view(),name="DeleteTourismCard"), 

#HOME PLANTATIONS 
    path('api/admin/AddEditPlantation/', views.AddEditPlantation.as_view(), name='AddEditPlantation'),
    path("api/admin/GetHomePlantations/",views.GetHomePlantations.as_view(),name="GetHomePlantations"), 
    path("api/admin/Get_ActiveHomePlantations/",views.Get_ActiveHomePlantations.as_view(),name="Get_ActiveHomePlantations"), 
    path("api/admin/GetHomePlantationByID/",views.GetHomePlantationByID.as_view(),name="GetHomePlantationByID"), 
    path("api/admin/UpdateHomePlantationStatus/",views.UpdateHomePlantationStatus.as_view(),name="UpdateHomePlantationStatus"), 
    path("api/admin/DeleteHomePlantation/",views.DeleteHomePlantation.as_view(),name="DeleteHomePlantation"), 

#ENQUIRY
    path('api/admin/getAll_enquiry/', views.GetEnquiry.as_view(), name='getAll_enquiry'),

]