# Generated by Django 4.1.3 on 2022-12-29 05:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bhakti_sadhna_api', '0002_remove_attendence_punch_out_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='first_name',
            field=models.CharField(max_length=25),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_name',
            field=models.CharField(max_length=25),
        ),
    ]
