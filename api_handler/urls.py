from django.conf.urls import include, url
from django.contrib import admin
from api_handler_app import views
from django.conf.urls import handler404
from django.conf.urls import handler500

handler404 = 'api_handler_app.views.page_not_found'
handler500 = 'api_handler_app.views.server_error'

admin.autodiscover()

'''This is a all api name url pattern'''
'''This Url used to call corresponding apiName method in views.py'''
urlpatterns = [
   url(r'^admin/', include(admin.site.urls)),
   url(r'^get_initial_token/', views.get_initial_token),
   url(r'^login_2fa/', views.get_login_2fa),
   url(r'^valid_pwd/',views.get_valid_pwd),
   url(r'^valid_ans/',views.get_valid_ans),
   url(r'^login_mode/', views.get_login_mode),
   url(r'^excel_property_update/', views.get_excel_property_update),
   url(r'^retrieve_all_pending_api/', views.get_retrieve_all_pending_api),
   url(r'^retrieve_all_success_or_failure_api/', views.get_retrieve_all_success_or_failure_api),
   url(r'^[a-zA-Z0-9_.-]+/', views.get_api_handler_request),
  ]