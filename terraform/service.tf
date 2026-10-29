resource "google_service_account" "app" {
  account_id   = "pd-app"
  display_name = "pii-auditor runtime"
}
resource "google_project_iam_member" "app_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_logs_write" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}
# Metadata only, project-wide: dataset locations, ACLs, table schemas. No row access here.
resource "google_project_iam_member" "app_bq_metadata" {
  project = var.project_id
  role    = "roles/bigquery.metadataViewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# --- canary: FAKE personal data in real BigQuery / GCS resources, to check the auditor against ground truth ---
resource "google_bigquery_dataset" "canary_us" {
  dataset_id                 = "pii_canary_us"
  location                   = "US"
  delete_contents_on_destroy = true
  labels                     = { env = "demo", owner = "platform" }
  access {
    role          = "OWNER"
    user_by_email = var.admin_email
  }
  access {
    role          = "READER"
    user_by_email = google_service_account.app.email
  }
}
resource "google_bigquery_dataset" "canary_eu" {
  dataset_id                 = "pii_canary_eu"
  location                   = "EU"
  delete_contents_on_destroy = true
  labels                     = { env = "demo", owner = "platform" }
  access {
    role          = "OWNER"
    user_by_email = var.admin_email
  }
  access {
    role          = "READER"
    user_by_email = google_service_account.app.email
  }
}
resource "google_bigquery_table" "customers" {
  dataset_id          = google_bigquery_dataset.canary_us.dataset_id
  table_id            = "customers"
  deletion_protection = false
  schema = jsonencode([
    { name = "customer_id", type = "INT64", mode = "NULLABLE" },
    { name = "full_name", type = "STRING", mode = "NULLABLE" },
    { name = "email", type = "STRING", mode = "NULLABLE" },
    { name = "phone", type = "STRING", mode = "NULLABLE" },
    { name = "ssn", type = "STRING", mode = "NULLABLE" },
    { name = "card_number", type = "STRING", mode = "NULLABLE" },
    { name = "signup_ip", type = "STRING", mode = "NULLABLE" },
    { name = "contact_info", type = "STRING", mode = "NULLABLE" },
    { name = "plan", type = "STRING", mode = "NULLABLE" },
  ])
}
resource "google_bigquery_table" "orders" {
  dataset_id          = google_bigquery_dataset.canary_us.dataset_id
  table_id            = "orders"
  deletion_protection = false
  schema = jsonencode([
    { name = "order_id", type = "INT64", mode = "NULLABLE" },
    { name = "customer_id", type = "INT64", mode = "NULLABLE" },
    { name = "total", type = "FLOAT64", mode = "NULLABLE" },
    { name = "status", type = "STRING", mode = "NULLABLE" },
    { name = "sku_code", type = "STRING", mode = "NULLABLE" },
  ])
}
resource "google_bigquery_table" "events" {
  dataset_id          = google_bigquery_dataset.canary_us.dataset_id
  table_id            = "events"
  deletion_protection = false
  schema = jsonencode([
    { name = "event_id", type = "STRING", mode = "NULLABLE" },
    { name = "is_credit_card", type = "BOOL", mode = "NULLABLE" },
    { name = "payment_type", type = "STRING", mode = "NULLABLE" },
    { name = "latency_ms", type = "FLOAT64", mode = "NULLABLE" },
  ])
}
resource "google_bigquery_table" "patients" {
  dataset_id          = google_bigquery_dataset.canary_eu.dataset_id
  table_id            = "patients"
  deletion_protection = false
  schema = jsonencode([
    { name = "patient_id", type = "INT64", mode = "NULLABLE" },
    { name = "email", type = "STRING", mode = "NULLABLE" },
    { name = "iban", type = "STRING", mode = "NULLABLE" },
    { name = "birth_date", type = "DATE", mode = "NULLABLE" },
    { name = "visit_note", type = "STRING", mode = "NULLABLE" },
  ])
}
# The scanner may read ROWS only from the canary datasets.
resource "google_bigquery_dataset_iam_member" "app_reads_us" {
  dataset_id = google_bigquery_dataset.canary_us.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.app.email}"
}
resource "google_bigquery_dataset_iam_member" "app_reads_eu" {
  dataset_id = google_bigquery_dataset.canary_eu.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.app.email}"
}

resource "google_storage_bucket" "canary" {
  name                        = "${var.project_id}-pii-canary"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = { env = "demo", owner = "platform" }
}
resource "google_storage_bucket_iam_member" "app_reads_canary" {
  bucket = google_storage_bucket.canary.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.app.email}"
}
# Bucket metadata (location, encryption) for the canary bucket only; the project-level securityReviewer role reads bucket IAM policies.
resource "google_storage_bucket_iam_member" "app_bucket_meta" {
  bucket = google_storage_bucket.canary.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_storage_bucket_object" "people" {
  name         = "exports/people.csv"
  bucket       = google_storage_bucket.canary.name
  content_type = "text/csv"
  content      = <<-EOT
    id,name,email,phone,ssn
    1,Alice Nguyen,alice.nguyen@example.com,(415) 555-2671,078-05-1120
    2,Bob Okafor,bob.okafor@example.org,(212) 555-0187,219-09-9999
    3,Carol Silva,carol.silva@example.net,(303) 555-0142,123-45-6789
    4,Dan Petrov,dan.petrov@example.io,(206) 555-0199,457-55-5462
  EOT
}
resource "google_storage_bucket_object" "readme" {
  name         = "docs/notes.txt"
  bucket       = google_storage_bucket.canary.name
  content_type = "text/plain"
  content      = "Quarterly summary: revenue grew 12 percent. Order ids look like ORD-48213. No personal data here."
}

resource "google_cloud_run_v2_service" "app" {
  count               = var.image != "" ? 1 : 0
  name                = "pii-auditor"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account                  = google_service_account.app.email
    timeout                          = "120s"
    max_instance_request_concurrency = 10
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      startup_probe {
        http_get { path = "/healthz" }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "PII_LLM"
        value = "vertex"
      }
      env {
        name  = "PII_ALLOWED_PROVIDERS"
        value = "vertex,none"
      }
      env {
        name  = "PII_PROJECTS"
        value = var.project_id
      }
      env {
        name  = "PII_DATASETS"
        value = "${google_bigquery_dataset.canary_us.dataset_id},${google_bigquery_dataset.canary_eu.dataset_id}"
      }
      env {
        name  = "PII_BUCKETS"
        value = google_storage_bucket.canary.name
      }
    }
  }
  depends_on = [
    google_project_iam_member.app_vertex,
    google_project_iam_member.app_bq_metadata,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.image != "" ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}
