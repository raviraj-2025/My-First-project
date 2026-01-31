'''
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .models import Category, SubCategory
from .serializers import CategorySerializer, SubCategorySerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import BillSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from .models import SubCategory, Category
from django.shortcuts import get_object_or_404



@api_view(['GET'])
def get_categories(request):
    categories = Category.objects.all()
    serializer = CategorySerializer(categories, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def get_subcategories(request, category_id):
    subs = SubCategory.objects.filter(category_id=category_id)
    serializer = SubCategorySerializer(subs, many=True)
    return Response(serializer.data)

@api_view(['POST'])
def save_bill(request):
    serializer = BillSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Bill saved successfully!"})
    return Response(serializer.errors, status=400)

@api_view(['GET'])
def get_products(request):
    products = SubCategory.objects.all()
    serializer = SubCategorySerializer(products, many=True)
    return Response(serializer.data)

class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username
        })
    
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db.models import Q
from .models import Bill
from .serializers import BillSerializer

@api_view(['GET'])
def search_bills(request):
    bill_no = request.GET.get('bill_no', None)
    customer_name = request.GET.get('customer_name', None)
    date = request.GET.get('date', None)

    filters = Q()
    if bill_no:
        filters &= Q(bill_no__icontains=bill_no)
    if customer_name:
        filters &= Q(customer_name__icontains=customer_name)
    if date:
        filters &= Q(created_at__date=date)  # date should be in YYYY-MM-DD format

    bills = Bill.objects.filter(filters)
    serializer = BillSerializer(bills, many=True)
    return Response(serializer.data)



# List all products (already had get_products) - keep or update
@api_view(['GET'])
def get_products(request):
    products = SubCategory.objects.all().select_related('category')
    serializer = SubCategorySerializer(products, many=True)
    return Response(serializer.data)


# Create a new product
@api_view(['POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def create_product(request):
    # expected payload: { "category": <id>, "name": "...", "price": 123.45 }
    serializer = SubCategorySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update product
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticatedOrReadOnly])
def update_product(request, pk):
    product = get_object_or_404(SubCategory, pk=pk)
    serializer = SubCategorySerializer(product, data=request.data, partial=('PATCH'==request.method))
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Delete product
@api_view(['DELETE'])
@permission_classes([IsAuthenticatedOrReadOnly])
def delete_product(request, pk):
    product = get_object_or_404(SubCategory, pk=pk)
    product.delete()
    return Response({"message": "Deleted"}, status=status.HTTP_204_NO_CONTENT)


from rest_framework import viewsets
from .models import SubCategory
from .serializers import ProductSerializer

class ProductViewSet(viewsets.ModelViewSet):
    queryset = SubCategory.objects.all()
    serializer_class = ProductSerializer
'''

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .models import Category, SubCategory, Bill, BillItem
from .serializers import CategorySerializer, SubCategorySerializer, BillSerializer, ProductSerializer
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticatedOrReadOnly
import random
import string

# ----------------- AUTHENTICATION VIEWS -----------------

@api_view(['POST'])
def custom_login(request):
    """
    Custom login view with better debugging
    """
    print("🔐 LOGIN ATTEMPT RECEIVED")
    
    username = request.data.get('username', '').strip()
    password = request.data.get('password', '').strip()
    
    #print(f" Username: '{username}'")
    #print(f" Password: '{password}'")
    
    if not username or not password:
        return Response(
            {'error': 'Username and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Check if user exists
        try:
            user = User.objects.get(username=username)
            #print(f" User found: {user.username}")
            #print(f" User is_active: {user.is_active}")
        except User.DoesNotExist:
            #print(" User does not exist")
            return Response(
                {'error': 'Invalid username or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        #print(f" Authentication result: {user}")
        
        if user is not None:
            # Get or create token
            token, created = Token.objects.get_or_create(user=user)
            #print(f" Token: {token.key}")
            
            return Response({
                'token': token.key,
                'user_id': user.id,
                'username': user.username,
                'message': 'Login successful'
            })
        else:
            # Test password manually for debugging
            user = User.objects.get(username=username)
            password_correct = user.check_password(password)
            #print(f" Manual password check: {password_correct}")
            
            return Response(
                {'error': 'Invalid username or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        #print(f" Login error: {str(e)}")
        return Response(
            {'error': f'Server error: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
def get_categories(request):
    #print(" Fetching categories...")
    categories = Category.objects.all()
    serializer = CategorySerializer(categories, many=True)
    #print(f" Found {len(categories)} categories")
    return Response(serializer.data)

@api_view(['GET'])
def get_subcategories(request, category_id):
    #print(f" Fetching subcategories for category {category_id}...")
    subs = SubCategory.objects.filter(category_id=category_id)
    serializer = SubCategorySerializer(subs, many=True)
    #print(f" Found {len(subs)} subcategories")
    return Response(serializer.data)

@api_view(['POST'])
def save_bill(request):
    print(" Saving bill...")
    serializer = BillSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        #print(" Bill saved successfully")
        return Response({"message": "Bill saved successfully!"})
    #print(" Bill save failed:", serializer.errors)
    return Response(serializer.errors, status=400)

# ----------------- PASSWORD MANAGEMENT VIEWS -----------------

@api_view(['POST'])
def forgot_password(request):
    """
    Simple password reset - generates a temporary password
    """
    username = request.data.get('username')
    if not username:
        return Response({"error": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username)
        # Generate a temporary password
        temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        user.set_password(temp_password)
        user.save()
        
        return Response({
            "message": f"Temporary password generated: {temp_password}. Please change it after login."
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change password for authenticated user
    """
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')
    
    if not old_password or not new_password:
        return Response({"error": "Both old and new password are required"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check old password
    if not user.check_password(old_password):
        return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Set new password
    user.set_password(new_password)
    user.save()
    
    return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)

# ----------------- BILL SEARCH VIEW -----------------

@api_view(['GET'])
def search_bills(request):
    bill_no = request.GET.get('bill_no', None)
    customer_name = request.GET.get('customer_name', None)
    date = request.GET.get('date', None)

    filters = Q()
    if bill_no:
        filters &= Q(bill_no__icontains=bill_no)
    if customer_name:
        filters &= Q(customer_name__icontains=customer_name)
    if date:
        filters &= Q(created_at__date=date)

    bills = Bill.objects.filter(filters)
    serializer = BillSerializer(bills, many=True)
    return Response(serializer.data)

# ----------------- PRODUCT MANAGEMENT VIEWS -----------------

@api_view(['GET'])
def get_products(request):
    """
    Get all products (subcategories)
    """
    print(" Fetching all products...")
    products = SubCategory.objects.all().select_related('category')
    serializer = SubCategorySerializer(products, many=True)
    print(f" Found {len(products)} products")
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_product(request):
    """
    Create a new product
    """
    print(" Creating new product...")
    serializer = SubCategorySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        print("Product created successfully")
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    print("Product creation failed:", serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_product_detail(request, pk):
    """
    Get single product detail
    """
    try:
        product = SubCategory.objects.get(pk=pk)
        serializer = SubCategorySerializer(product)
        return Response(serializer.data)
    except SubCategory.DoesNotExist:
        return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_product(request, pk):
    """
    Update product
    """
    try:
        product = SubCategory.objects.get(pk=pk)
        serializer = SubCategorySerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except SubCategory.DoesNotExist:
        return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_product(request, pk):
    """
    Delete product
    """
    try:
        product = SubCategory.objects.get(pk=pk)
        product.delete()
        return Response({"message": "Product deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    except SubCategory.DoesNotExist:
        return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

# ----------------- VIEWSET FOR PRODUCTS -----------------

class ProductViewSet(viewsets.ModelViewSet):
    queryset = SubCategory.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]