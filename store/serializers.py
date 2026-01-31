from rest_framework import serializers
from .models import Category, SubCategory, Bill, BillItem


# --------------------- CATEGORY ---------------------
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']


# --------------------- SUBCATEGORY ---------------------
class SubCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SubCategory
        fields = ['id', 'category', 'name', 'price']


# --------------------- BILL & BILL ITEMS ---------------------
class BillItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillItem
        fields = ['product_name', 'quantity', 'price', 'total']


class BillSerializer(serializers.ModelSerializer):
    items = BillItemSerializer(many=True)

    class Meta:
        model = Bill
        fields = [
            'bill_no',
            'customer_name',
            'customer_mobile',
            'customer_email',
            'subtotal',
            'tax',
            'total',
            'items'
        ]

    def create(self, validated_data):
        # Extract nested item data from main payload
        items_data = validated_data.pop('items')

        # Create Bill instance
        bill = Bill.objects.create(**validated_data)

        # Create each BillItem linked to Bill
        for item_data in items_data:
            BillItem.objects.create(bill=bill, **item_data)

        return bill


from rest_framework import serializers
from .models import SubCategory

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubCategory
        fields = ['id', 'category', 'name', 'price']
