# Specialized Agent Prompts for Development Workflows

> **Purpose**: Advanced agent prompts for specific development tasks and analysis  
> **Date**: 2025-06-21  
> **Usage**: Use these prompts for specialized development assistance and automation

## 🔒 **Daily Security Review Agent Prompt**

### **Comprehensive Security Analysis**
```
Please conduct a comprehensive daily security review of this codebase with the following focus areas:

## AUTHENTICATION & AUTHORIZATION ANALYSIS
1. **JWT Implementation Review**:
   - Check token generation, validation, and refresh mechanisms
   - Verify proper secret key management and rotation
   - Validate token expiration and blacklisting
   - Review trust level implementation and calculation
   - Ensure proper claims validation and sanitization

2. **Access Control Verification**:
   - Review RBAC implementation and policy enforcement
   - Check protected route configurations
   - Validate permission-based access controls
   - Verify role hierarchy and inheritance
   - Test authorization bypass scenarios

3. **Session Management Security**:
   - Review session storage and lifecycle management
   - Check concurrent session handling
   - Validate session timeout mechanisms
   - Verify proper session invalidation on logout
   - Test session fixation protection

## INPUT VALIDATION & XSS PREVENTION
4. **Input Sanitization Review**:
   - Check all user input validation points
   - Verify proper data sanitization before storage
   - Review output encoding mechanisms
   - Test for SQL injection vulnerabilities
   - Validate file upload security (if applicable)

5. **XSS Protection Analysis**:
   - Review Content Security Policy implementation
   - Check for dangerous innerHTML usage
   - Verify proper HTML escaping
   - Test dynamic content rendering security
   - Validate URL parameter handling

## INFRASTRUCTURE SECURITY
6. **Configuration Security**:
   - Review environment variable handling
   - Check for hardcoded secrets or credentials
   - Validate secure default configurations
   - Review CORS and security headers
   - Check TLS/SSL configuration

7. **Dependency Security**:
   - Scan for known vulnerabilities in dependencies
   - Check for outdated packages with security issues
   - Review transitive dependency risks
   - Validate dependency integrity and authenticity
   - Check for abandoned or unmaintained dependencies

## ERROR HANDLING & INFORMATION DISCLOSURE
8. **Secure Error Handling**:
   - Review error message content for information leakage
   - Check stack trace exposure in production
   - Validate proper error logging without sensitive data
   - Test error response consistency
   - Verify graceful failure mechanisms

9. **Audit & Logging Security**:
   - Review audit trail completeness and integrity
   - Check for sensitive data in logs
   - Validate log access controls
   - Test log tampering protection
   - Verify audit event correlation

## ZERO TRUST PRINCIPLES
10. **Continuous Verification**:
    - Review device attestation implementation
    - Check trust level calculation accuracy
    - Validate continuous re-authentication triggers
    - Test privilege escalation controls
    - Verify least privilege enforcement

## DELIVERABLE FORMAT
Please provide your analysis in this format:

### 🚨 CRITICAL SECURITY ISSUES (Fix Immediately)
- [Issue description with file:line references]
- [Specific remediation steps]
- [Security impact assessment]

### ⚠️ HIGH PRIORITY ISSUES (Fix This Week)
- [Issue description with file:line references]
- [Recommended fixes with code examples]
- [Risk mitigation strategies]

### 📋 MEDIUM PRIORITY IMPROVEMENTS (Next Sprint)
- [Enhancement recommendations]
- [Best practice implementations]
- [Security hardening opportunities]

### ✅ SECURITY STRENGTHS IDENTIFIED
- [Well-implemented security controls]
- [Best practices already in place]
- [Effective security patterns]

### 📊 SECURITY SCORECARD
- Authentication Security: [Score/10]
- Authorization Controls: [Score/10]
- Input Validation: [Score/10]
- Infrastructure Security: [Score/10]
- Error Handling: [Score/10]
- Zero Trust Implementation: [Score/10]
- **Overall Security Score: [Score/60]**

### 🔄 NEXT SECURITY REVIEW FOCUS
- [Specific areas to prioritize in next review]
- [Security testing recommendations]
- [Monitoring and alerting improvements]

Provide specific file paths, line numbers, and code examples for all findings. Focus on actionable recommendations with clear implementation steps.
```

## 🔍 **Code Quality Assessment Agent Prompt**

### **Comprehensive Code Quality Analysis**
```
Please conduct a thorough code quality assessment of this codebase focusing on maintainability, performance, and best practices:

## ARCHITECTURE & DESIGN ANALYSIS
1. **Design Patterns & Principles**:
   - Evaluate SOLID principles adherence
   - Review design pattern usage and appropriateness
   - Check separation of concerns implementation
   - Assess coupling and cohesion levels
   - Validate dependency injection patterns

2. **Code Organization**:
   - Review directory structure and naming conventions
   - Check module/package organization clarity
   - Evaluate import/dependency management
   - Assess code reusability and modularity
   - Validate abstraction levels

## CODE MAINTAINABILITY
3. **Readability & Clarity**:
   - Review variable and function naming conventions
   - Check code complexity and cyclomatic complexity
   - Evaluate comment quality and documentation
   - Assess code self-documentation
   - Review magic numbers and constants usage

4. **Technical Debt Assessment**:
   - Identify code smells and anti-patterns
   - Review TODO/FIXME comments and their urgency
   - Check for duplicated code blocks
   - Assess legacy code sections needing refactoring
   - Evaluate dead code elimination opportunities

## PERFORMANCE ANALYSIS
5. **Algorithm Efficiency**:
   - Review time complexity of critical algorithms
   - Check for N+1 query problems in database interactions
   - Evaluate memory usage patterns
   - Assess caching strategy effectiveness
   - Review async/sync operation balance

6. **Resource Management**:
   - Check proper resource cleanup (connections, files, etc.)
   - Review memory leak potential
   - Evaluate garbage collection impact
   - Check thread safety and concurrency issues
   - Assess scalability bottlenecks

## TESTING QUALITY
7. **Test Coverage & Strategy**:
   - Evaluate test coverage percentage and quality
   - Review test pyramid implementation (unit/integration/e2e)
   - Check test isolation and independence
   - Assess test maintainability and clarity
   - Validate edge case coverage

8. **Test Quality Metrics**:
   - Review test naming conventions
   - Check test data management strategies
   - Evaluate mock usage appropriateness
   - Assess test execution speed
   - Validate CI/CD test integration

## LANGUAGE-SPECIFIC BEST PRACTICES
9. **Technology Stack Optimization**:
   - Review framework usage best practices
   - Check library and dependency appropriateness
   - Evaluate language-specific idioms usage
   - Assess modern language feature adoption
   - Validate tooling configuration (linters, formatters)

10. **Error Handling & Resilience**:
    - Review exception handling patterns
    - Check error propagation strategies
    - Evaluate retry and circuit breaker implementations
    - Assess graceful degradation mechanisms
    - Validate logging and observability

## DOCUMENTATION & KNOWLEDGE SHARING
11. **Documentation Quality**:
    - Review API documentation completeness
    - Check code comment appropriateness
    - Evaluate README and setup instructions
    - Assess architecture documentation
    - Validate decision records and rationale

## DELIVERABLE FORMAT
Please provide your analysis in this format:

### 🔴 CRITICAL QUALITY ISSUES (Immediate Attention)
- [Issue description with file:line references]
- [Refactoring recommendations]
- [Impact on maintainability/performance]

### 🟡 REFACTORING OPPORTUNITIES (High Impact)
- [Code sections needing improvement]
- [Specific refactoring strategies]
- [Expected benefits and effort estimation]

### 🟢 OPTIMIZATION OPPORTUNITIES (Performance & Efficiency)
- [Performance improvement suggestions]
- [Resource optimization recommendations]
- [Caching and efficiency enhancements]

### 📚 BEST PRACTICE IMPROVEMENTS
- [Modern pattern implementations]
- [Industry standard adoptions]
- [Tooling and process enhancements]

### ✅ QUALITY STRENGTHS IDENTIFIED
- [Well-implemented patterns and practices]
- [Exemplary code sections worth highlighting]
- [Effective architectural decisions]

### 📊 CODE QUALITY SCORECARD
- Architecture & Design: [Score/10]
- Code Maintainability: [Score/10]
- Performance Optimization: [Score/10]
- Testing Quality: [Score/10]
- Best Practices Adherence: [Score/10]
- Documentation Quality: [Score/10]
- **Overall Quality Score: [Score/60]**

### 🎯 PRIORITY IMPROVEMENT ROADMAP
1. **Week 1**: [Highest impact, lowest effort improvements]
2. **Week 2-3**: [Medium complexity refactoring tasks]
3. **Month 1**: [Major architectural improvements]
4. **Quarter 1**: [Long-term technical debt resolution]

### 🔄 CONTINUOUS IMPROVEMENT SUGGESTIONS
- [Automated quality gates recommendations]
- [Code review checklist updates]
- [Developer tooling improvements]
- [Training and knowledge sharing opportunities]

Provide specific file paths, line numbers, and code examples for all findings. Include estimated effort for improvements and expected benefits.
```

## 🏗️ **Architecture Review Agent Prompt**

### **Comprehensive Architecture Analysis**
```
Please conduct a thorough architecture review of this system focusing on scalability, maintainability, and alignment with best practices:

## SYSTEM ARCHITECTURE ANALYSIS
1. **Overall Design Assessment**:
   - Evaluate architectural patterns (microservices, monolith, serverless)
   - Review service boundaries and responsibilities
   - Assess data flow and communication patterns
   - Check system coupling and cohesion
   - Validate architectural decision rationale

2. **Scalability & Performance Design**:
   - Review horizontal and vertical scaling strategies
   - Assess load balancing and distribution patterns
   - Check caching layers and strategies
   - Evaluate database design and indexing
   - Analyze bottleneck identification and mitigation

## SERVICE DESIGN EVALUATION
3. **Domain-Driven Design Implementation**:
   - Review bounded context definitions
   - Check aggregate design and consistency
   - Evaluate domain model richness
   - Assess ubiquitous language usage
   - Validate business logic placement

4. **API Design & Integration**:
   - Review REST API design principles
   - Check versioning and backward compatibility
   - Evaluate error handling and status codes
   - Assess documentation and discoverability
   - Validate security integration

## DATA ARCHITECTURE REVIEW
5. **Database Design & Management**:
   - Review data modeling and normalization
   - Check query optimization and indexing strategies
   - Evaluate transaction management
   - Assess backup and disaster recovery
   - Validate data migration strategies

6. **Data Flow & Processing**:
   - Review data pipeline design
   - Check event sourcing and CQRS implementation
   - Evaluate batch vs stream processing decisions
   - Assess data consistency patterns
   - Validate data governance practices

## INFRASTRUCTURE & DEPLOYMENT
7. **Container & Orchestration Strategy**:
   - Review containerization approach
   - Check Kubernetes deployment patterns
   - Evaluate service mesh implementation
   - Assess configuration management
   - Validate secrets management

8. **CI/CD & DevOps Practices**:
   - Review build and deployment pipelines
   - Check testing automation integration
   - Evaluate monitoring and alerting setup
   - Assess infrastructure as code practices
   - Validate GitOps implementation

## SECURITY ARCHITECTURE
9. **Security Design Patterns**:
   - Review Zero Trust implementation
   - Check authentication and authorization architecture
   - Evaluate network security design
   - Assess data protection strategies
   - Validate compliance framework integration

10. **Resilience & Fault Tolerance**:
    - Review circuit breaker patterns
    - Check retry and timeout strategies
    - Evaluate graceful degradation mechanisms
    - Assess disaster recovery design
    - Validate monitoring and alerting architecture

## TECHNOLOGY STACK EVALUATION
11. **Technology Choices Assessment**:
    - Evaluate framework and library selections
    - Check technology stack coherence
    - Assess future maintainability
    - Review vendor lock-in risks
    - Validate upgrade and migration paths

## DELIVERABLE FORMAT
Please provide your analysis in this format:

### 🚨 ARCHITECTURAL RISKS (Immediate Attention)
- [Critical design flaws with system-wide impact]
- [Scalability bottlenecks requiring urgent attention]
- [Security architecture vulnerabilities]

### 📈 SCALABILITY CONCERNS (High Priority)
- [Performance bottlenecks and scaling limitations]
- [Resource utilization inefficiencies]
- [Data architecture scaling challenges]

### 🔧 DESIGN IMPROVEMENTS (Medium Priority)
- [Service design optimization opportunities]
- [API design enhancements]
- [Data flow improvements]

### 🎯 MODERNIZATION OPPORTUNITIES
- [Technology stack upgrade recommendations]
- [Pattern implementation improvements]
- [Infrastructure optimization suggestions]

### ✅ ARCHITECTURAL STRENGTHS
- [Well-designed system components]
- [Effective architectural patterns]
- [Smart technology choices]

### 📊 ARCHITECTURE ASSESSMENT SCORECARD
- System Design: [Score/10]
- Scalability Design: [Score/10]
- Data Architecture: [Score/10]
- Security Architecture: [Score/10]
- Infrastructure Design: [Score/10]
- Technology Stack: [Score/10]
- **Overall Architecture Score: [Score/60]**

### 🗺️ ARCHITECTURE EVOLUTION ROADMAP
**Phase 1 (0-3 months)**: [Immediate improvements and quick wins]
**Phase 2 (3-6 months)**: [Medium complexity architectural changes]
**Phase 3 (6-12 months)**: [Major architectural evolution initiatives]
**Phase 4 (12+ months)**: [Long-term strategic architecture goals]

### 📋 IMPLEMENTATION RECOMMENDATIONS
- [Specific technical implementations with effort estimates]
- [Migration strategies for architectural changes]
- [Risk mitigation approaches for major changes]
- [Team skill development recommendations]

Provide specific system diagrams, component references, and implementation examples. Include effort estimates and business impact assessments for all recommendations.
```

## ⚡ **Performance Optimization Agent Prompt**

### **Comprehensive Performance Analysis**
```
Please conduct a thorough performance analysis of this system focusing on speed, efficiency, and resource optimization:

## APPLICATION PERFORMANCE ANALYSIS
1. **Response Time Optimization**:
   - Analyze API endpoint response times
   - Review database query performance
   - Check frontend loading and rendering speeds
   - Evaluate third-party service integration latency
   - Assess network communication efficiency

2. **Throughput & Concurrency**:
   - Review concurrent request handling
   - Check thread pool and connection pool sizing
   - Evaluate async vs sync operation balance
   - Assess load balancing effectiveness
   - Validate rate limiting and throttling

## DATABASE PERFORMANCE REVIEW
3. **Query Optimization**:
   - Analyze slow query logs and execution plans
   - Review index usage and optimization opportunities
   - Check for N+1 query problems
   - Evaluate ORM usage efficiency
   - Assess batch operation implementations

4. **Database Design Performance**:
   - Review table design and normalization impact
   - Check partitioning and sharding strategies
   - Evaluate connection pooling configuration
   - Assess transaction isolation and locking
   - Validate backup and maintenance impact

## MEMORY & RESOURCE OPTIMIZATION
5. **Memory Usage Analysis**:
   - Review memory allocation patterns
   - Check for memory leaks and excessive usage
   - Evaluate garbage collection impact
   - Assess caching strategy effectiveness
   - Validate resource cleanup practices

6. **CPU & Processing Optimization**:
   - Analyze CPU usage patterns and hotspots
   - Review algorithm complexity and efficiency
   - Check for unnecessary computations
   - Evaluate parallel processing opportunities
   - Assess background job performance

## CACHING STRATEGY REVIEW
7. **Caching Implementation**:
   - Review caching layers and strategies
   - Check cache hit rates and effectiveness
   - Evaluate cache invalidation mechanisms
   - Assess distributed caching implementation
   - Validate CDN and static asset optimization

8. **Data Access Optimization**:
   - Review data fetching patterns
   - Check pagination and lazy loading implementation
   - Evaluate data serialization efficiency
   - Assess compression usage
   - Validate data prefetching strategies

## FRONTEND PERFORMANCE
9. **Bundle & Asset Optimization**:
   - Analyze bundle sizes and composition
   - Review code splitting implementation
   - Check asset compression and minification
   - Evaluate lazy loading strategies
   - Assess image and media optimization

10. **Runtime Performance**:
    - Review JavaScript execution performance
    - Check rendering optimization (React/DOM)
    - Evaluate memory usage in browser
    - Assess event handling efficiency
    - Validate progressive loading implementation

## INFRASTRUCTURE PERFORMANCE
11. **Network & Communication**:
    - Review network latency and bandwidth usage
    - Check HTTP/2 and compression utilization
    - Evaluate API design for efficiency
    - Assess microservice communication overhead
    - Validate load balancer configuration

12. **Scaling & Resource Management**:
    - Review auto-scaling configuration
    - Check resource allocation and limits
    - Evaluate container performance
    - Assess storage I/O performance
    - Validate monitoring and alerting thresholds

## DELIVERABLE FORMAT
Please provide your analysis in this format:

### 🔴 CRITICAL PERFORMANCE ISSUES (Immediate Fix Required)
- [Performance bottlenecks causing user impact]
- [Resource exhaustion problems]
- [Scaling limitations with urgent business impact]

### 🟡 HIGH IMPACT OPTIMIZATIONS (This Sprint)
- [Database query optimizations with specific improvements]
- [Caching implementations with expected gains]
- [Algorithm improvements with complexity reductions]

### 🟢 MEDIUM IMPACT IMPROVEMENTS (Next Month)
- [Infrastructure optimizations]
- [Code refactoring for performance]
- [Monitoring and alerting enhancements]

### 📊 PERFORMANCE METRICS BASELINE
- **Current Performance Stats**:
  - Average API Response Time: [ms]
  - 95th Percentile Response Time: [ms]
  - Database Query Average: [ms]
  - Memory Usage Average: [%]
  - CPU Usage Average: [%]
  - Cache Hit Rate: [%]

### 🎯 OPTIMIZATION TARGETS
- **Target Performance Goals**:
  - API Response Time: [target ms] (improvement: [%])
  - Database Performance: [target ms] (improvement: [%])
  - Memory Optimization: [target %] (reduction: [%])
  - Cache Efficiency: [target %] (improvement: [%])

### 📈 PERFORMANCE IMPROVEMENT ROADMAP
**Week 1**: [Quick wins and immediate optimizations]
**Week 2-4**: [Database and caching improvements]
**Month 2**: [Infrastructure and scaling optimizations]
**Quarter 1**: [Major architectural performance changes]

### 🛠️ IMPLEMENTATION RECOMMENDATIONS
- [Specific optimization techniques with code examples]
- [Tool recommendations for performance monitoring]
- [Load testing strategies and benchmarks]
- [Performance budget and SLA recommendations]

### 📊 EXPECTED PERFORMANCE GAINS
- [Quantified improvements for each optimization]
- [Business impact of performance improvements]
- [Cost-benefit analysis of optimization efforts]
- [Risk assessment for performance changes]

Provide specific metrics, file references, and measurable improvement targets. Include before/after performance comparisons where possible and implementation effort estimates.
```

## 📋 **Usage Guidelines for Specialized Prompts**

### **When to Use Each Prompt**

1. **Daily Security Review**: 
   - Use daily or every few days for security-critical applications
   - Run before major releases or deployments
   - Use when integrating new security features
   - Apply after security incidents or vulnerability discoveries

2. **Code Quality Assessment**:
   - Use weekly during active development
   - Run before code reviews or major refactoring
   - Apply when onboarding new team members
   - Use for technical debt assessment sessions

3. **Architecture Review**:
   - Use monthly or quarterly for established systems
   - Run before major feature additions
   - Apply when planning system scaling
   - Use for technology migration planning

4. **Performance Optimization**:
   - Use when performance issues are identified
   - Run before and after major feature releases
   - Apply when scaling system capacity
   - Use for regular performance health checks

### **Customization Guidelines**

1. **Adapt to Your Stack**: Modify prompts to focus on your specific technologies
2. **Set Context**: Include information about your system scale and requirements
3. **Focus Areas**: Emphasize specific areas of concern for your project
4. **Metrics**: Adjust target metrics based on your SLA and requirements

### **Integration with Development Workflow**

1. **Sprint Planning**: Use assessment results to plan improvement tasks
2. **Code Reviews**: Apply findings to improve review criteria
3. **CI/CD**: Integrate automated checks based on prompt recommendations
4. **Documentation**: Update architecture and security documentation based on findings

These specialized prompts provide comprehensive analysis frameworks that can significantly improve code quality, security posture, architectural soundness, and system performance when applied regularly.