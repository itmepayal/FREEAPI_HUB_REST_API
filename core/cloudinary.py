import cloudinary.uploader
from django.conf import settings

cloudinary.config(
    cloud_name=settings.CLOUDINARY_CLOUD_NAME,
    api_key=settings.CLOUDINARY_API_KEY,
    api_secret=settings.CLOUDINARY_API_SECRET,
    secure=True
)

def upload_to_cloudinary(file, folder="default", use_filename=True, unique_filename=True, overwrite=False):
    try:
        result = cloudinary.uploader.upload(
            file,
            folder=folder,
            use_filename=use_filename,
            unique_filename=unique_filename,
            overwrite=overwrite
        )
        return result.get("secure_url")
    except Exception as e:
        raise Exception(f"Cloudinary upload failed: {str(e)}")
