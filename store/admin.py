from django.contrib import admin
from .models import Category, SubCategory, Bill, BillItem

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')


@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'category', 'price')


class BillItemInline(admin.TabularInline):
    model = BillItem
    extra = 1


@admin.register(Bill)
class BillAdmin(admin.ModelAdmin):
    list_display = ('bill_no', 'customer_name', 'customer_mobile', 'subtotal', 'tax', 'total', 'created_at')
    inlines = [BillItemInline]
