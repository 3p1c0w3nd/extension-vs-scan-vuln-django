import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

interface Vulnerability {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  code: string;
  description: string;
  recommendation: string;
  owaspLink: string;
  fixMethod: string;
}

export function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand(
    'django-security-scanner.scan',
    async () => {
      const vulnerabilities: Vulnerability[] = [];
      
      if (!vscode.workspace.workspaceFolders) {
        vscode.window.showErrorMessage('No hay carpeta de proyecto abierta');
        return;
      }

      vscode.window.showInformationMessage('Iniciando escaneo de seguridad Django...');

      const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
      
      // Escanear archivos Python
      await scanPythonFiles(workspaceRoot, vulnerabilities);
      
      // Escanear configuraciones
      await scanSettings(workspaceRoot, vulnerabilities);
      
      // Escanear templates
      await scanTemplates(workspaceRoot, vulnerabilities);
      
      // Escanear APIs
      await scanAPIs(workspaceRoot, vulnerabilities);
      
      // Escanear malas prácticas de configuración
      await scanConfigurationBestPractices(workspaceRoot, vulnerabilities);
      
      // Mostrar resultados
      displayResults(vulnerabilities, workspaceRoot);
    }
  );

  context.subscriptions.push(disposable);
}

async function scanPythonFiles(root: string, vulnerabilities: Vulnerability[]) {
  const files = findFiles(root, '.py');
  
  for (const file of files) {
    const content = fs.readFileSync(file, 'utf-8');
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      // SQL Injection - uso de raw queries sin parametrización
      if (line.includes('.raw(') && (line.includes('%s') || line.includes('format('))) {
        vulnerabilities.push({
          type: 'SQL Injection',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Uso de consultas SQL raw con interpolación de strings',
          recommendation: 'Usa parámetros seguros: .raw("SELECT * FROM tabla WHERE id = %s", [user_input])',
          owaspLink: 'https://owasp.org/www-community/attacks/SQL_Injection',
          fixMethod: 'Utiliza consultas parametrizadas con placeholders seguros. En Django ORM, usa el método .raw() con parámetros en una lista separada. Evita la interpolación directa de strings.'
        });
      }

      // XSS - render HTML sin escape
      if (line.includes('mark_safe(') || line.includes('|safe')) {
        vulnerabilities.push({
          type: 'XSS',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Uso de mark_safe o filtro |safe que puede permitir XSS',
          recommendation: 'Evita mark_safe con datos de usuario. Usa escape() o déjalo escapar automáticamente',
          owaspLink: 'https://owasp.org/www-community/attacks/xss/',
          fixMethod: 'Nunca uses mark_safe() con contenido proporcionado por el usuario. Django escapa automáticamente el contenido HTML. Si necesitas renderizar HTML seguro, usa bibliotecas como bleach para sanitizar el contenido.'
        });
      }

      // CSRF - vistas sin protección
      if (line.includes('@csrf_exempt')) {
        vulnerabilities.push({
          type: 'CSRF',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Vista deshabilitando protección CSRF',
          recommendation: 'Elimina @csrf_exempt y usa {% csrf_token %} en formularios',
          owaspLink: 'https://owasp.org/www-community/attacks/csrf',
          fixMethod: 'Elimina el decorador @csrf_exempt. Incluye {% csrf_token %} en todos los formularios POST. Para APIs, usa autenticación basada en tokens o verifica el origen de la solicitud.'
        });
      }

      // Comando injection
      if ((line.includes('os.system(') || line.includes('subprocess.call(')) && 
          (line.includes('request.') || line.includes('POST') || line.includes('GET'))) {
        vulnerabilities.push({
          type: 'Command Injection',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Ejecución de comandos del sistema con datos de usuario',
          recommendation: 'Valida y sanitiza entrada. Usa subprocess.run() con shell=False y lista de argumentos',
          owaspLink: 'https://owasp.org/www-community/attacks/Command_Injection',
          fixMethod: 'Valida y sanitiza todas las entradas del usuario. Usa subprocess.run() con shell=False y pasa argumentos como lista. Evita concatenar strings para formar comandos.'
        });
      }

      // Path Traversal
      if ((line.includes('open(') || line.includes('os.path.join(')) && 
          (line.includes('request.') || line.includes('GET') || line.includes('POST'))) {
        vulnerabilities.push({
          type: 'Path Traversal',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Posible manipulación de rutas de archivos',
          recommendation: 'Valida rutas con os.path.abspath() y verifica que estén dentro del directorio permitido',
          owaspLink: 'https://owasp.org/www-community/attacks/Path_Traversal',
          fixMethod: 'Usa os.path.abspath() para normalizar rutas. Verifica que la ruta resultante esté dentro del directorio base permitido. Considera usar bibliotecas como pathlib para manejo seguro de rutas.'
        });
      }

      // Insecure Deserialization
      if (line.includes('pickle.loads(') && (line.includes('request.') || line.includes('POST') || line.includes('GET'))) {
        vulnerabilities.push({
          type: 'Insecure Deserialization',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Deserialización insegura con pickle de datos no confiables',
          recommendation: 'Usa JSON en lugar de pickle para datos de usuario',
          owaspLink: 'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
          fixMethod: 'Nunca deserialices datos no confiables con pickle. Usa formatos seguros como JSON. Si necesitas serialización, considera usar bibliotecas como json con validación de esquema.'
        });
      }

      // Hardcoded secrets
      if (line.match(/SECRET_KEY\s*=\s*['"][^'"]{20,}['"]/)) {
        vulnerabilities.push({
          type: 'Hardcoded Secret',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim().substring(0, 50) + '...',
          description: 'SECRET_KEY hardcodeada en código',
          recommendation: 'Usa variables de entorno: SECRET_KEY = os.environ.get("SECRET_KEY")',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication',
          fixMethod: 'Nunca hardcodees claves secretas en el código. Usa variables de entorno o servicios de gestión de secretos como Azure Key Vault. Carga la SECRET_KEY desde el entorno en tiempo de ejecución.'
        });
      }

      // Debug habilitado
      if (line.match(/DEBUG\s*=\s*True/)) {
        vulnerabilities.push({
          type: 'Debug Mode Enabled',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'DEBUG = True en configuración',
          recommendation: 'Cambia a DEBUG = False en producción',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration',
          fixMethod: 'Establece DEBUG = False en entornos de producción. Usa variables de entorno para controlar la configuración. Implementa manejo adecuado de errores sin exponer información sensible.'
        });
      }

      // ALLOWED_HOSTS débil
      if (line.match(/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/) || 
          line.match(/ALLOWED_HOSTS\s*=\s*\[\s*\]/)) {
        vulnerabilities.push({
          type: 'Weak ALLOWED_HOSTS',
          severity: 'medium',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'ALLOWED_HOSTS mal configurado',
          recommendation: 'Especifica hosts permitidos: ALLOWED_HOSTS = ["midominio.com"]',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration',
          fixMethod: 'Especifica explícitamente los hosts permitidos en ALLOWED_HOSTS. Nunca uses ["*"] en producción. Incluye todos los dominios válidos, incluyendo subdominios si es necesario.'
        });
      }

      // Mass assignment
      if (line.includes('**request.POST') || line.includes('**request.data')) {
        vulnerabilities.push({
          type: 'Mass Assignment',
          severity: 'medium',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Asignación masiva sin filtrar campos',
          recommendation: 'Define explícitamente campos permitidos o usa serializers con fields específicos',
          owaspLink: 'https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet',
          fixMethod: 'Define explícitamente los campos permitidos. Usa ModelForm con fields o exclude. Para APIs, usa serializers de Django REST framework con fields específicos. Nunca asignes directamente **request.POST a un modelo.'
        });
      }
    });
  }
}

async function scanSettings(root: string, vulnerabilities: Vulnerability[]) {
  const settingsFiles = findFiles(root, 'settings.py');
  
  for (const file of settingsFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      // Middleware de seguridad faltante
      if (line.includes('MIDDLEWARE')) {
        const middlewareContent = content.substring(content.indexOf('MIDDLEWARE'));
        
        if (!middlewareContent.includes('SecurityMiddleware')) {
          vulnerabilities.push({
            type: 'Missing Security Middleware',
            severity: 'medium',
            file: file,
            line: index + 1,
            code: 'MIDDLEWARE configuration',
            description: 'SecurityMiddleware no está configurado',
            recommendation: 'Agrega "django.middleware.security.SecurityMiddleware" a MIDDLEWARE',
            owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration',
            fixMethod: 'Agrega django.middleware.security.SecurityMiddleware al inicio de la lista MIDDLEWARE en settings.py. Este middleware proporciona varias protecciones de seguridad importantes.'
          });
        }
      }

      // Configuraciones de seguridad
      if (!content.includes('SECURE_SSL_REDIRECT = True')) {
        vulnerabilities.push({
          type: 'HTTP Not Redirected to HTTPS',
          severity: 'medium',
          file: file,
          line: 1,
          code: 'Missing SECURE_SSL_REDIRECT',
          description: 'No hay redirección automática a HTTPS',
          recommendation: 'Agrega SECURE_SSL_REDIRECT = True en producción',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
          fixMethod: 'Agrega SECURE_SSL_REDIRECT = True en settings.py para forzar redirección HTTPS. Asegúrate de que tu servidor web (nginx, Apache) esté configurado para SSL.'
        });
      }

      if (!content.includes('SECURE_HSTS_SECONDS')) {
        vulnerabilities.push({
          type: 'Missing HSTS',
          severity: 'medium',
          file: file,
          line: 1,
          code: 'Missing HSTS configuration',
          description: 'HSTS no configurado',
          recommendation: 'Agrega SECURE_HSTS_SECONDS = 31536000 (1 año)',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
          fixMethod: 'Agrega SECURE_HSTS_SECONDS = 31536000 para habilitar HSTS por 1 año. Comienza con un valor bajo inicialmente y aumenta gradualmente. Requiere HTTPS configurado.'
        });
      }

      if (!content.includes('SESSION_COOKIE_SECURE = True')) {
        vulnerabilities.push({
          type: 'Insecure Session Cookie',
          severity: 'medium',
          file: file,
          line: 1,
          code: 'Missing SESSION_COOKIE_SECURE',
          description: 'Cookies de sesión sin flag Secure',
          recommendation: 'Agrega SESSION_COOKIE_SECURE = True',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
          fixMethod: 'Agrega SESSION_COOKIE_SECURE = True para enviar cookies de sesión solo sobre HTTPS. También configura SESSION_COOKIE_HTTPONLY = True para prevenir acceso desde JavaScript.'
        });
      }

      if (!content.includes('CSRF_COOKIE_SECURE = True')) {
        vulnerabilities.push({
          type: 'Insecure CSRF Cookie',
          severity: 'medium',
          file: file,
          line: 1,
          code: 'Missing CSRF_COOKIE_SECURE',
          description: 'Cookie CSRF sin flag Secure',
          recommendation: 'Agrega CSRF_COOKIE_SECURE = True',
          owaspLink: 'https://owasp.org/www-community/attacks/csrf',
          fixMethod: 'Agrega CSRF_COOKIE_SECURE = True para enviar cookies CSRF solo sobre HTTPS. También configura CSRF_COOKIE_HTTPONLY = True para mayor seguridad.'
        });
      }
    });
  }
}

async function scanTemplates(root: string, vulnerabilities: Vulnerability[]) {
  const templates = findFiles(root, '.html');
  
  for (const file of templates) {
    const content = fs.readFileSync(file, 'utf-8');
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      // XSS en templates
      if (line.includes('|safe') && !line.includes('{#')) {
        vulnerabilities.push({
          type: 'XSS in Template',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Uso del filtro |safe en template',
          recommendation: 'Evita |safe con contenido de usuario. Usa autoescape',
          owaspLink: 'https://owasp.org/www-community/attacks/xss/',
          fixMethod: 'Nunca uses el filtro |safe con contenido proporcionado por usuarios. Django escapa automáticamente el contenido HTML. Si necesitas renderizar HTML, sanitiza el contenido con bibliotecas como bleach.'
        });
      }

      // CSRF token faltante en forms
      if (line.includes('<form') && line.includes('method="post"')) {
        const formContent = content.substring(content.indexOf(line));
        if (!formContent.includes('csrf_token')) {
          vulnerabilities.push({
            type: 'Missing CSRF Token',
            severity: 'high',
            file: file,
            line: index + 1,
            code: line.trim(),
            description: 'Formulario POST sin {% csrf_token %}',
            recommendation: 'Agrega {% csrf_token %} dentro del formulario',
            owaspLink: 'https://owasp.org/www-community/attacks/csrf',
            fixMethod: 'Agrega {% csrf_token %} dentro de cada formulario POST. El token debe estar entre las etiquetas <form> y </form>. Para APIs, considera usar autenticación basada en tokens.'
          });
        }
      }
    });
  }
}

async function scanAPIs(root: string, vulnerabilities: Vulnerability[]) {
  const apiFiles = findFiles(root, '.py').filter(file => 
    file.includes('views.py') || file.includes('urls.py') || file.includes('serializers.py') || file.includes('api.py')
  );
  
  for (const file of apiFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      // API1:2019 Broken Object Level Authorization
      if (line.includes('get_object_or_404') && !line.includes('request.user')) {
        vulnerabilities.push({
          type: 'Broken Object Level Authorization (API1)',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Acceso a objetos sin verificar permisos del usuario',
          recommendation: 'Verifica que el objeto pertenezca al usuario: if obj.user != request.user: raise PermissionDenied',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Implementa verificación de autorización a nivel de objeto. Verifica que el usuario tenga permisos para acceder al recurso específico. Usa permisos de Django o verifica manualmente la propiedad del objeto.'
        });
      }

      // API2:2019 Broken Authentication
      if (line.includes('authenticate') && !line.includes('is_active')) {
        vulnerabilities.push({
          type: 'Broken Authentication (API2)',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Autenticación sin verificar si el usuario está activo',
          recommendation: 'Verifica user.is_active después de authenticate()',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication',
          fixMethod: 'Después de authenticate(), verifica user.is_active. Si el usuario no está activo, no permitas el login. Considera usar django-allauth para autenticación más robusta.'
        });
      }

      // API3:2019 Excessive Data Exposure
      if (line.includes('serializer.data') && !line.includes('fields=')) {
        vulnerabilities.push({
          type: 'Excessive Data Exposure (API3)',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Serializador exponiendo todos los campos sin restricción',
          recommendation: 'Define fields específicos en el serializador: fields = ["field1", "field2"]',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Define explícitamente los campos a exponer en el serializador usando Meta.fields. Nunca uses "__all__" para campos sensibles. Usa diferentes serializadores para diferentes contextos.'
        });
      }

      // API4:2019 Lack of Resources & Rate Limiting
      if (!content.includes('throttling') && (line.includes('APIView') || line.includes('ViewSet'))) {
        vulnerabilities.push({
          type: 'Lack of Rate Limiting (API4)',
          severity: 'medium',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'API sin control de tasa de solicitudes',
          recommendation: 'Implementa throttling: throttle_classes = [UserRateThrottle]',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Implementa throttling en Django REST framework. Define throttle_classes en tus vistas o configura throttling global en settings.py. Usa AnonRateThrottle y UserRateThrottle.'
        });
      }

      // API5:2019 Broken Function Level Authorization
      if (line.includes('@permission_classes') && line.includes('AllowAny')) {
        vulnerabilities.push({
          type: 'Broken Function Level Authorization (API5)',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Permisos demasiado permisivos en endpoints críticos',
          recommendation: 'Usa permisos específicos: permission_classes = [IsAuthenticated]',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Implementa permisos apropiados basados en el rol del usuario. Usa IsAuthenticated para endpoints que requieren login, IsAdminUser para administradores, o permisos personalizados.'
        });
      }

      // API6:2019 Mass Assignment
      if (line.includes('serializer.save()') && !line.includes('validated_data')) {
        vulnerabilities.push({
          type: 'Mass Assignment (API6)',
          severity: 'high',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Asignación masiva sin validar campos permitidos',
          recommendation: 'Usa validated_data y define campos explícitamente',
          owaspLink: 'https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet',
          fixMethod: 'Usa serializer.validated_data en lugar de request.data directamente. Define explícitamente los campos permitidos en el serializador. Implementa validaciones personalizadas si es necesario.'
        });
      }

      // API7:2019 Security Misconfiguration
      if (line.includes('DEBUG = True') && file.includes('settings.py')) {
        vulnerabilities.push({
          type: 'Security Misconfiguration (API7)',
          severity: 'medium',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'DEBUG habilitado en producción',
          recommendation: 'Deshabilita DEBUG en producción',
          owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration',
          fixMethod: 'Establece DEBUG = False en entornos de producción. Usa variables de entorno para controlar la configuración. Implementa manejo adecuado de errores sin exponer información sensible.'
        });
      }

      // API8:2019 Injection
      if (line.includes('eval(') || line.includes('exec(')) {
        vulnerabilities.push({
          type: 'Injection (API8)',
          severity: 'critical',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Uso de eval() o exec() con datos de usuario',
          recommendation: 'Evita eval/exec. Usa alternativas seguras',
          owaspLink: 'https://owasp.org/www-community/attacks/Code_Injection',
          fixMethod: 'Nunca uses eval() o exec() con datos proporcionados por el usuario. Si necesitas ejecutar código dinámicamente, considera usar bibliotecas seguras o refactoriza para evitar la necesidad.'
        });
      }

      // API9:2019 Improper Assets Management
      if (line.includes('api/v1/') && !line.includes('api/v2/')) {
        vulnerabilities.push({
          type: 'Improper Assets Management (API9)',
          severity: 'medium',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'Versiones antiguas de API sin depreciación',
          recommendation: 'Implementa versioning adecuado y deprecia versiones viejas',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Implementa un esquema de versioning claro (URL, header, etc.). Documenta las versiones soportadas y establece políticas de depreciación. Monitorea el uso de versiones antiguas.'
        });
      }

      // API10:2019 Insufficient Logging & Monitoring
      if (!content.includes('logging') && (line.includes('APIView') || line.includes('ViewSet'))) {
        vulnerabilities.push({
          type: 'Insufficient Logging (API10)',
          severity: 'low',
          file: file,
          line: index + 1,
          code: line.trim(),
          description: 'API sin logging adecuado para monitoreo',
          recommendation: 'Implementa logging para requests/responses importantes',
          owaspLink: 'https://owasp.org/www-project-api-security/',
          fixMethod: 'Configura logging en Django settings. Registra eventos importantes como autenticaciones fallidas, cambios de datos, y errores. Usa herramientas como Sentry para monitoreo.'
        });
      }
    });
  }
}

async function scanConfigurationBestPractices(root: string, vulnerabilities: Vulnerability[]) {
  const settingsFiles = findFiles(root, 'settings.py');
  
  for (const file of settingsFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    
    // CORS mal configurado
    if (content.includes('CORS_ORIGIN_ALLOW_ALL = True')) {
      vulnerabilities.push({
        type: 'CORS Misconfiguration',
        severity: 'high',
        file: file,
        line: 1,
        code: 'CORS_ORIGIN_ALLOW_ALL = True',
        description: 'CORS permite todos los orígenes',
        recommendation: 'Especifica orígenes permitidos: CORS_ORIGIN_WHITELIST = ["https://example.com"]',
        owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration',
        fixMethod: 'Nunca uses CORS_ORIGIN_ALLOW_ALL = True en producción. Especifica explícitamente los orígenes permitidos en CORS_ORIGIN_WHITELIST. Configura CORS_ALLOWED_ORIGINS para Django 4.0+.'
      });
    }

    // No usar HTTPS
    if (!content.includes('SECURE_SSL_REDIRECT = True')) {
      vulnerabilities.push({
        type: 'No HTTPS Redirection',
        severity: 'medium',
        file: file,
        line: 1,
        code: 'Missing SECURE_SSL_REDIRECT',
        description: 'No hay redirección automática a HTTPS',
        recommendation: 'Agrega SECURE_SSL_REDIRECT = True',
        owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
        fixMethod: 'Agrega SECURE_SSL_REDIRECT = True en settings.py para forzar redirección HTTPS. Asegúrate de que tu servidor web esté configurado para SSL.'
      });
    }

    // Cookies inseguras
    if (!content.includes('SESSION_COOKIE_HTTPONLY = True')) {
      vulnerabilities.push({
        type: 'Insecure Session Cookies',
        severity: 'medium',
        file: file,
        line: 1,
        code: 'Missing SESSION_COOKIE_HTTPONLY',
        description: 'Cookies de sesión accesibles via JavaScript',
        recommendation: 'Agrega SESSION_COOKIE_HTTPONLY = True',
        owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
        fixMethod: 'Agrega SESSION_COOKIE_HTTPONLY = True para prevenir acceso a cookies desde JavaScript. También configura SESSION_COOKIE_SECURE = True para HTTPS.'
      });
    }

    // No validar inputs
    if (!content.includes('django.middleware.validation')) {
      vulnerabilities.push({
        type: 'Missing Input Validation',
        severity: 'medium',
        file: file,
        line: 1,
        code: 'Missing validation middleware',
        description: 'Middleware de validación no configurado',
        recommendation: 'Agrega validación de inputs en forms y serializers',
        owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection',
        fixMethod: 'Implementa validación de inputs en Django Forms, ModelForms y Serializers. Usa validadores personalizados para datos complejos. Nunca confíes en la validación del frontend.'
      });
    }

    // Base de datos sin encriptación
    if (content.includes('DATABASES') && !content.includes('sslmode=require')) {
      vulnerabilities.push({
        type: 'Unencrypted Database Connection',
        severity: 'high',
        file: file,
        line: 1,
        code: 'DATABASES configuration',
        description: 'Conexión a base de datos sin SSL/TLS',
        recommendation: 'Habilita SSL en la configuración de DATABASES',
        owaspLink: 'https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure',
        fixMethod: 'Configura SSL/TLS para conexiones de base de datos. Para PostgreSQL, agrega sslmode=require. Para MySQL, configura OPTIONS con ssl. Usa certificados válidos en producción.'
      });
    }
  }
}

function findFiles(dir: string, extension: string): string[] {
  const files: string[] = [];
  
  function traverse(currentPath: string) {
    if (!fs.existsSync(currentPath)) return;
    
    const items = fs.readdirSync(currentPath);
    
    for (const item of items) {
      const fullPath = path.join(currentPath, item);
      
      // Ignorar directorios comunes
      if (item === 'node_modules' || item === 'venv' || item === '__pycache__' || item === '.git') {
        continue;
      }
      
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        traverse(fullPath);
      } else if (fullPath.endsWith(extension)) {
        files.push(fullPath);
      }
    }
  }
  
  traverse(dir);
  return files;
}

function displayResults(vulnerabilities: Vulnerability[], workspaceRoot: string) {
  if (vulnerabilities.length === 0) {
    vscode.window.showInformationMessage('�?No se encontraron vulnerabilidades');
    return;
  }

  // Agrupar por severidad
  const critical = vulnerabilities.filter(v => v.severity === 'critical');
  const high = vulnerabilities.filter(v => v.severity === 'high');
  const medium = vulnerabilities.filter(v => v.severity === 'medium');
  const low = vulnerabilities.filter(v => v.severity === 'low');

  // Crear panel de resultados
  const panel = vscode.window.createWebviewPanel(
    'djangoSecurityResults',
    'Django Security Scan Results',
    vscode.ViewColumn.One,
    {}
  );

  const htmlContent = getResultsHtml(vulnerabilities, critical, high, medium, low);
  panel.webview.html = htmlContent;

  // Generar archivo HTML en el proyecto
  const reportPath = path.join(workspaceRoot, 'security-report.html');
  fs.writeFileSync(reportPath, htmlContent);
  vscode.window.showInformationMessage(`📄 Reporte HTML generado: ${reportPath}`);
}

function getResultsHtml(
  all: Vulnerability[],
  critical: Vulnerability[],
  high: Vulnerability[],
  medium: Vulnerability[],
  low: Vulnerability[]
): string {
  const renderVulnerability = (v: Vulnerability) => `
    <div class="vulnerability ${v.severity}">
      <div class="vuln-header">
        <span class="vuln-type">${v.type}</span>
        <span class="severity-badge ${v.severity}">${v.severity.toUpperCase()}</span>
      </div>
      <div class="vuln-location">${v.file}:${v.line}</div>
      <div class="vuln-code"><code>${escapeHtml(v.code)}</code></div>
      <div class="vuln-description">${v.description}</div>
      <div class="vuln-recommendation"><strong>💡 Recomendación:</strong> ${v.recommendation}</div>
      <div class="vuln-fix-method"><strong>🔧 Cómo arreglarlo:</strong> ${v.fixMethod}</div>
      <div class="vuln-owasp-link"><strong>📖 Más información:</strong> <a href="${v.owaspLink}" target="_blank">${v.owaspLink}</a></div>
    </div>
  `;

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          padding: 20px;
          background: #1e1e1e;
          color: #d4d4d4;
        }
        h1 { color: #4ec9b0; }
        h2 { 
          color: #569cd6;
          margin-top: 30px;
          border-bottom: 2px solid #569cd6;
          padding-bottom: 5px;
        }
        .summary {
          background: #252526;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 30px;
          border-left: 4px solid #4ec9b0;
        }
        .summary-stats {
          display: flex;
          gap: 20px;
          margin-top: 15px;
        }
        .stat {
          padding: 10px 15px;
          border-radius: 5px;
          font-weight: bold;
        }
        .stat.critical { background: #d32f2f; }
        .stat.high { background: #f57c00; }
        .stat.medium { background: #fbc02d; color: #000; }
        .stat.low { background: #388e3c; }
        .vulnerability {
          background: #252526;
          border-left: 4px solid #888;
          padding: 15px;
          margin-bottom: 20px;
          border-radius: 5px;
        }
        .vulnerability.critical { border-left-color: #d32f2f; }
        .vulnerability.high { border-left-color: #f57c00; }
        .vulnerability.medium { border-left-color: #fbc02d; }
        .vulnerability.low { border-left-color: #388e3c; }
        .vuln-header {
          display: flex;
          justify-content: space-between;
          margin-bottom: 10px;
        }
        .vuln-type {
          font-size: 18px;
          font-weight: bold;
          color: #4ec9b0;
        }
        .severity-badge {
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 12px;
          font-weight: bold;
        }
        .severity-badge.critical { background: #d32f2f; }
        .severity-badge.high { background: #f57c00; }
        .severity-badge.medium { background: #fbc02d; color: #000; }
        .severity-badge.low { background: #388e3c; }
        .vuln-location {
          color: #808080;
          font-size: 14px;
          margin-bottom: 10px;
        }
        .vuln-code {
          background: #1e1e1e;
          padding: 10px;
          border-radius: 4px;
          margin: 10px 0;
          font-family: 'Consolas', 'Courier New', monospace;
          overflow-x: auto;
        }
        .vuln-description {
          margin: 10px 0;
          line-height: 1.5;
        }
        .vuln-recommendation {
          background: #2d2d30;
          padding: 10px;
          border-radius: 4px;
          margin-top: 10px;
          border-left: 3px solid #4ec9b0;
        }
        .vuln-fix-method {
          background: #2d2d30;
          padding: 10px;
          border-radius: 4px;
          margin-top: 10px;
          border-left: 3px solid #569cd6;
        }
        .vuln-owasp-link {
          background: #2d2d30;
          padding: 10px;
          border-radius: 4px;
          margin-top: 10px;
          border-left: 3px solid #f57c00;
        }
        .vuln-owasp-link a {
          color: #4ec9b0;
          text-decoration: none;
        }
        .vuln-owasp-link a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <h1>🔒 Django Security Scanner - Resultados</h1>
      
      <div class="summary">
        <h3>📊 Resumen del Escaneo</h3>
        <p>Total de vulnerabilidades encontradas: <strong>${all.length}</strong></p>
        <div class="summary-stats">
          <div class="stat critical">Críticas: ${critical.length}</div>
          <div class="stat high">Altas: ${high.length}</div>
          <div class="stat medium">Medias: ${medium.length}</div>
          <div class="stat low">Bajas: ${low.length}</div>
        </div>
      </div>

      ${critical.length > 0 ? `
        <h2>🚨 Vulnerabilidades Críticas</h2>
        ${critical.map(renderVulnerability).join('')}
      ` : ''}

      ${high.length > 0 ? `
        <h2>⚠️ Vulnerabilidades Altas</h2>
        ${high.map(renderVulnerability).join('')}
      ` : ''}

      ${medium.length > 0 ? `
        <h2>�?Vulnerabilidades Medias</h2>
        ${medium.map(renderVulnerability).join('')}
      ` : ''}

      ${low.length > 0 ? `
        <h2>ℹ️ Vulnerabilidades Bajas</h2>
        ${low.map(renderVulnerability).join('')}
      ` : ''}
    </body>
    </html>
  `;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function deactivate() {}