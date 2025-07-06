# CI/CD Pipeline y Testing

Este documento describe el pipeline de CI/CD y la estrategia de testing para Huginn Network Profiler.

## Pipeline de CI/CD

El pipeline se ejecuta en GitHub Actions y incluye los siguientes jobs:

### 🔨 Build
- **Propósito**: Compilar todo el workspace
- **Dependencias**: libpcap-dev
- **Cache**: Cargo registry y target directory
- **Comando**: `cargo build --verbose`

### 🧪 Test
- **Propósito**: Ejecutar todos los tests del workspace
- **Dependencias**: libpcap-dev
- **Cache**: Cargo registry y target directory
- **Comandos**:
  - `cargo test --verbose`
  - `cargo test --verbose --all-features`
  - `cargo test --verbose --doc`

### 📝 Format
- **Propósito**: Verificar formato del código
- **Cache**: Cargo registry y target directory
- **Comando**: `cargo fmt -- --check`

### 🔍 Lint
- **Propósito**: Análisis estático del código
- **Dependencias**: libpcap-dev
- **Cache**: Cargo registry y target directory
- **Comando**: `cargo clippy --all-targets --all-features -- -D warnings`

### 📚 Examples
- **Propósito**: Verificar que los ejemplos compilen
- **Dependencias**: libpcap-dev
- **Cache**: Cargo registry y target directory
- **Comandos**:
  - `cargo build --examples --verbose`
  - Verificación condicional de ejemplos específicos

### 🔒 Security
- **Propósito**: Auditoría de seguridad
- **Cache**: Cargo registry y target directory
- **Herramienta**: cargo-audit
- **Comando**: `cargo audit`

### 📊 Coverage
- **Propósito**: Generar reporte de cobertura de tests
- **Dependencias**: libpcap-dev
- **Cache**: Cargo registry y target directory
- **Herramienta**: cargo-tarpaulin
- **Integración**: Codecov

### ✅ CI Success
- **Propósito**: Verificar que todos los jobs críticos pasen
- **Dependencias**: build, test, format, lint, examples, security
- **Comportamiento**: Falla si algún job crítico falla

## Estructura de Tests

### huginn-core (6 tests)
- **test_version_is_set**: Verifica que la versión esté configurada
- **test_analyzer_creation**: Verifica creación del analizador
- **test_analyzer_with_config**: Verifica analizador con configuración personalizada
- **test_traffic_profile_creation**: Verifica creación de perfiles de tráfico
- **test_analyzer_config_default**: Verifica configuración por defecto
- **test_huginn_error_creation**: Verifica creación de errores

### huginn-collector (9 tests)
- **test_version_is_set**: Verifica que la versión esté configurada
- **test_collector_config_default**: Verifica configuración por defecto
- **test_collector_config_new**: Verifica creación con interfaz específica
- **test_collector_config_validation**: Verifica validación de configuración
- **test_collector_error_creation**: Verifica creación de errores
- **test_collector_error_config**: Verifica errores de configuración
- **test_collector_config_builder**: Verifica patrón builder
- **test_bridge_forwards_messages**: Test de integración del bridge
- **test_bridge_handles_sender_drop**: Test de manejo de desconexión

### huginn-api (8 tests)
- **test_version_is_set**: Verifica que la versión esté configurada
- **test_server_config_default**: Verifica configuración por defecto
- **test_server_config_interface**: Verifica configuración de interfaz
- **test_api_server_creation**: Verifica creación del servidor
- **test_api_error_creation**: Verifica creación de errores
- **test_api_error_configuration**: Verifica errores de configuración
- **test_app_state_creation**: Verifica creación del estado de la app
- **test_socket_addr_parsing**: Verifica parsing de direcciones

## Optimizaciones del Pipeline

### Cache Strategy
- **Cargo Registry**: `~/.cargo/registry`
- **Cargo Git**: `~/.cargo/git`
- **Target Directory**: `target`
- **Key**: `${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}`

### Paralelización
- Todos los jobs principales se ejecutan en paralelo
- Solo `ci-success` depende de los otros jobs
- `coverage` se ejecuta independientemente

### Conditional Examples
- Los ejemplos se verifican solo si existen
- Evita fallos por ejemplos faltantes
- Permite desarrollo incremental

## Comandos Útiles

### Ejecutar todos los tests
```bash
cargo test --workspace --verbose
```

### Ejecutar tests de un crate específico
```bash
cargo test -p huginn-core --verbose
cargo test -p huginn-collector --verbose
cargo test -p huginn-api --verbose
```

### Ejecutar tests con cobertura
```bash
cargo tarpaulin --verbose --all-features --workspace --timeout 120
```

### Verificar formato
```bash
cargo fmt -- --check
```

### Ejecutar linter
```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Auditoría de seguridad
```bash
cargo audit
```

## Configuración Local

### Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y libpcap-dev

# macOS
brew install libpcap

# Arch Linux
sudo pacman -S libpcap
```

### Herramientas de Testing
```bash
# Instalar cargo-tarpaulin para cobertura
cargo install cargo-tarpaulin

# Instalar cargo-audit para auditoría
cargo install cargo-audit
```

## Integración con IDEs

### VS Code
- Instalar extensión rust-analyzer
- Configurar tasks.json para ejecutar tests
- Usar extensión Coverage Gutters para visualizar cobertura

### IntelliJ/CLion
- Plugin Rust habilitado
- Configurar run configurations para tests
- Integración con cargo clippy

## Métricas de Calidad

### Cobertura de Tests
- **Objetivo**: >80% de cobertura
- **Reporte**: Generado por cargo-tarpaulin
- **Visualización**: Codecov dashboard

### Calidad del Código
- **Linting**: cargo clippy con warnings como errores
- **Formato**: cargo fmt estricto
- **Seguridad**: cargo audit sin vulnerabilidades

### Performance
- **Cache Hit Rate**: >90% en CI
- **Tiempo de Build**: <5 minutos
- **Tiempo de Tests**: <2 minutos

## Troubleshooting

### Tests Fallan Localmente
1. Verificar dependencias del sistema
2. Limpiar cache: `cargo clean`
3. Actualizar dependencias: `cargo update`

### CI Falla en Specific Job
1. Verificar logs específicos del job
2. Revisar cambios en dependencias
3. Verificar compatibilidad de versiones

### Cache Issues
1. Invalidar cache manualmente en GitHub
2. Verificar Cargo.lock cambios
3. Revisar configuración de cache keys

## Roadmap

### Próximas Mejoras
- [ ] Tests de integración end-to-end
- [ ] Benchmarks de performance
- [ ] Tests de carga para el collector
- [ ] Fuzzing para parsers
- [ ] Property-based testing

### Herramientas Adicionales
- [ ] cargo-deny para licencias
- [ ] cargo-outdated para dependencias
- [ ] cargo-udeps para dependencias no usadas
- [ ] cargo-machete para features no usadas 