from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'products', views.ProductViewSet)

urlpatterns = [
    # Include router URLs - these will be available at /api/products/
    path('api/', include(router.urls)),
    
    # Authentication endpoints
    path('api/login/', views.custom_login, name='login'),
    path('api/forgot-password/', views.forgot_password, name='forgot_password'),
    path('api/change-password/', views.change_password, name='change_password'),
    
    # Categories endpoints
    path('api/categories/', views.get_categories, name='categories'),
    path('api/subcategories/<int:category_id>/', views.get_subcategories, name='subcategories'),
    
    # Bills endpoints
    path('api/save-bill/', views.save_bill, name='save_bill'),
    path('api/search-bills/', views.search_bills, name='search_bills'),
    
    # Additional product endpoints (if needed alongside the ViewSet)
    path('api/products/', views.get_products, name='get_products'),
    path('api/products/create/', views.create_product, name='create_product'),
    path('api/products/<int:pk>/', views.get_product_detail, name='product_detail'),
    path('api/products/<int:pk>/update/', views.update_product, name='update_product'),
    path('api/products/<int:pk>/delete/', views.delete_product, name='delete_product'),
]