DELETE FROM product_modules WHERE namespace = 'terrasell';
DROP INDEX IF EXISTS idx_product_modules_namespace;
DROP TABLE IF EXISTS product_modules;
