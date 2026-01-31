from django.db import models

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    price = models.FloatField()

    def __str__(self):
        return f"{self.name} - {self.category.name}"

from django.db import models

class Bill(models.Model):
    bill_no = models.CharField(max_length=20)
    customer_name = models.CharField(max_length=100)
    customer_mobile = models.CharField(max_length=15)
    customer_email = models.CharField(max_length=254)
    subtotal = models.FloatField()
    tax = models.FloatField(default=0)
    total = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Bill {self.bill_no} - {self.customer_name}"


class BillItem(models.Model):
    bill = models.ForeignKey(Bill, related_name='items', on_delete=models.CASCADE)
    product_name = models.CharField(max_length=100)
    quantity = models.IntegerField()
    price = models.FloatField()
    total = models.FloatField()

    def __str__(self):
        return f"{self.product_name} ({self.quantity})"
