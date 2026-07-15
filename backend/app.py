from flask import Flask, make_response

from core.config  import SECRET_KEY, COOKIE_SETTINGS, CYCENTRA_DB_URL
from core.helpers import add_cors_headers, HostAwareSessionInterface

from blueprints.auth.oauth          import auth_bp
from blueprints.oidc.provider       import oidc_bp
from blueprints.rbac.manager        import rbac_bp
from blueprints.platform.routes     import platform_bp
from blueprints.asm.scanner         import asm_bp
from blueprints.system.routes       import system_bp, reapply_o365_if_missing
from blueprints.backup.routes       import backup_bp
from blueprints.scheduler.routes    import scheduler_bp, init_scheduler
from blueprints.marketplace.routes  import marketplace_bp
from blueprints.audit.routes        import audit_bp
from blueprints.sso.routes          import sso_bp
from blueprints.benchmark.routes    import benchmark_bp
from blueprints.comp.routes         import comp_bp
from blueprints.cases.routes        import cases_bp
from blueprints.integrations.routes import integrations_bp
from blueprints.edr.routes          import edr_bp, init_edr
from blueprints.itam.routes         import itam_bp, init_itam_tables
from blueprints.collector.routes    import collector_bp, ensure_tables as ensure_collector_tables
from blueprints.connectors.routes   import connectors_bp, ensure_tables as ensure_connector_tables
from blueprints.detection_rules.routes import detection_rules_bp, ensure_tables as ensure_detection_rule_tables
from siem_proxy                     import siem_bp

try: from tenant_manager import validate_tenant
except ImportError: validate_tenant = lambda x: x

def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    app.config.update(COOKIE_SETTINGS)
    app.session_interface = HostAwareSessionInterface()
    for bp in (auth_bp, oidc_bp, rbac_bp, platform_bp, asm_bp, siem_bp, system_bp,
               backup_bp, scheduler_bp, marketplace_bp, audit_bp, sso_bp, benchmark_bp,
               comp_bp, cases_bp, integrations_bp, edr_bp, itam_bp, collector_bp, connectors_bp,
               detection_rules_bp):
        app.register_blueprint(bp)
    init_edr(app)
    for ensure_fn in (init_itam_tables, ensure_collector_tables, ensure_connector_tables,
                      ensure_detection_rule_tables):
        try: ensure_fn(CYCENTRA_DB_URL)
        except Exception: pass
    try:
        from cy_comp.models import ensure_tables; ensure_tables()
        from cy_comp.services.questionnaire import seed_templates; seed_templates(force=True)
    except Exception as exc:
        import logging; logging.getLogger(__name__).warning("cy_comp init failed (non-fatal): %s", exc)

    init_scheduler(app)
    reapply_o365_if_missing()

    @app.after_request
    def _cors(response):
        return add_cors_headers(response)

    @app.route('/api/<path:p>',  methods=['OPTIONS'])
    @app.route('/auth/<path:p>', methods=['OPTIONS'])
    @app.route('/oidc/<path:p>', methods=['OPTIONS'])
    def _options(p):
        return add_cors_headers(make_response('', 204))

    return app

app = create_app()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5252, debug=False)
