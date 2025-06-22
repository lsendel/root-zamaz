# Routine Analysis Prompts for Agent-Driven Development

> **Purpose**: Standardized prompts for routine project analysis and improvement  
> **Date**: 2025-06-21  
> **Usage**: Copy these prompts for regular project health checks and improvements

## 🎯 **Quick Start Prompts**

### **Daily Health Check Prompt**
```
Please perform a comprehensive health check of this project:

1. **Security Analysis**:
   - Scan for hardcoded secrets or credentials
   - Check authentication and authorization implementations
   - Verify input validation and sanitization
   - Review error messages for information leakage

2. **Code Quality Review**:
   - Check for code smells and anti-patterns
   - Verify SOLID principles adherence
   - Review test coverage and testing strategy
   - Analyze dependency management

3. **Performance Assessment**:
   - Identify potential bottlenecks
   - Review database query patterns
   - Check for N+1 queries or inefficient algorithms
   - Analyze resource usage patterns

4. **Documentation Status**:
   - Verify README and documentation accuracy
   - Check if API documentation is up-to-date
   - Review CLAUDE.md files for completeness

Provide specific recommendations with file paths and line numbers where applicable.
```

### **Weekly Architecture Review Prompt**
```
Conduct a weekly architecture review focusing on:

1. **System Design**:
   - Evaluate current architecture against best practices
   - Identify potential scalability issues
   - Review service boundaries and coupling
   - Check for proper separation of concerns

2. **Technology Stack Assessment**:
   - Verify dependencies are up-to-date and secure
   - Check for deprecated packages or practices
   - Evaluate technology choices for current requirements

3. **Infrastructure Analysis**:
   - Review deployment configurations
   - Check monitoring and alerting setup
   - Verify backup and disaster recovery plans
   - Assess resource allocation and costs

4. **Future Planning**:
   - Identify technical debt that needs addressing
   - Suggest improvements for next sprint
   - Highlight opportunities for optimization

Create a prioritized action plan with effort estimates.
```

### **Monthly Security Audit Prompt**
```
Perform a comprehensive security audit including:

1. **Authentication & Authorization**:
   - Review JWT implementation and token management
   - Check RBAC policies and enforcement
   - Verify session management security
   - Analyze device attestation and trust levels

2. **Input Validation & XSS Prevention**:
   - Test all input endpoints for injection attacks
   - Verify proper data sanitization
   - Check for XSS vulnerabilities in frontend
   - Review CSRF protection mechanisms

3. **Infrastructure Security**:
   - Analyze Docker and Kubernetes configurations
   - Review network policies and segmentation
   - Check secrets management practices
   - Verify TLS/SSL configurations

4. **Compliance & Audit**:
   - Review audit logging completeness
   - Check GDPR compliance measures
   - Verify data retention policies
   - Analyze access control patterns

Provide a security scorecard with specific remediation steps.
```

## 🔄 **Development Workflow Prompts**

### **Pre-Development Analysis Prompt**
```
Before starting new feature development, analyze:

1. **Current State Assessment**:
   - Review existing similar functionality
   - Identify reusable components and patterns
   - Check for potential conflicts with current features
   - Analyze impact on existing architecture

2. **Design Considerations**:
   - Suggest appropriate design patterns
   - Recommend testing strategy
   - Identify security considerations
   - Plan database schema changes if needed

3. **Implementation Planning**:
   - Break down into manageable tasks
   - Estimate development effort
   - Identify dependencies and prerequisites
   - Plan rollback strategy

4. **Quality Gates**:
   - Define acceptance criteria
   - Plan testing approach
   - Set performance benchmarks
   - Establish monitoring requirements

Create a detailed implementation plan with todo list.
```

### **Post-Development Review Prompt**
```
After completing feature development, conduct a review covering:

1. **Code Quality**:
   - Review code against established patterns
   - Check for proper error handling
   - Verify logging and monitoring
   - Ensure adequate test coverage

2. **Security Validation**:
   - Test authentication and authorization
   - Verify input validation
   - Check for potential vulnerabilities
   - Review audit logging

3. **Performance Verification**:
   - Run performance benchmarks
   - Check database query efficiency
   - Verify resource usage
   - Test under load conditions

4. **Documentation & Maintenance**:
   - Update documentation
   - Create operational runbooks
   - Document troubleshooting procedures
   - Update monitoring dashboards

Provide a go/no-go recommendation for deployment.
```

## 🚀 **Specialized Analysis Prompts**

### **Database Optimization Prompt**
```
Analyze database performance and optimization opportunities:

1. **Query Performance**:
   - Identify slow queries and bottlenecks
   - Review index usage and optimization
   - Check for N+1 query problems
   - Analyze query execution plans

2. **Schema Design**:
   - Review table relationships and normalization
   - Check constraint definitions
   - Verify data types and sizing
   - Analyze partitioning strategies

3. **Connection Management**:
   - Review connection pooling configuration
   - Check for connection leaks
   - Analyze concurrent access patterns
   - Verify transaction management

4. **Monitoring & Maintenance**:
   - Set up query performance monitoring
   - Plan maintenance windows
   - Create backup and recovery procedures
   - Establish capacity planning metrics

Provide specific optimization recommendations with implementation steps.
```

### **Frontend Performance Audit Prompt**
```
Conduct a comprehensive frontend performance analysis:

1. **Bundle Analysis**:
   - Analyze bundle size and composition
   - Identify unnecessary dependencies
   - Check for code splitting opportunities
   - Review tree shaking effectiveness

2. **Runtime Performance**:
   - Profile component rendering performance
   - Identify memory leaks
   - Check for unnecessary re-renders
   - Analyze JavaScript execution time

3. **User Experience**:
   - Test loading performance
   - Verify responsive design
   - Check accessibility compliance
   - Analyze user interaction patterns

4. **Optimization Opportunities**:
   - Suggest lazy loading strategies
   - Recommend caching improvements
   - Identify prefetching opportunities
   - Plan progressive enhancement

Create a performance improvement roadmap with metrics.
```

### **API Design Review Prompt**
```
Review API design and implementation quality:

1. **RESTful Design**:
   - Verify REST principles adherence
   - Check resource naming conventions
   - Review HTTP method usage
   - Analyze response status codes

2. **Documentation & Contracts**:
   - Verify OpenAPI specification accuracy
   - Check endpoint documentation completeness
   - Review request/response examples
   - Validate schema definitions

3. **Security & Validation**:
   - Review authentication mechanisms
   - Check authorization enforcement
   - Verify input validation
   - Analyze rate limiting

4. **Versioning & Evolution**:
   - Review API versioning strategy
   - Check backward compatibility
   - Plan deprecation procedures
   - Analyze change impact

Provide API quality scorecard with improvement recommendations.
```

## 🔧 **Maintenance & Operations Prompts**

### **Infrastructure Health Check Prompt**
```
Assess infrastructure health and operational readiness:

1. **System Health**:
   - Check service availability and uptime
   - Review resource utilization trends
   - Analyze error rates and patterns
   - Verify backup and recovery procedures

2. **Monitoring & Alerting**:
   - Review monitoring coverage completeness
   - Check alert threshold appropriateness
   - Verify escalation procedures
   - Analyze incident response times

3. **Security Posture**:
   - Check security patches and updates
   - Review access control implementations
   - Verify network security configurations
   - Analyze security incident patterns

4. **Capacity Planning**:
   - Analyze growth trends
   - Review scaling capabilities
   - Plan resource allocation
   - Estimate cost implications

Create an operational health dashboard with action items.
```

### **Dependency Audit Prompt**
```
Conduct a comprehensive dependency audit:

1. **Security Vulnerabilities**:
   - Scan for known security vulnerabilities
   - Check dependency freshness
   - Review update and patch status
   - Analyze transitive dependencies

2. **License Compliance**:
   - Review dependency licenses
   - Check for license conflicts
   - Verify compliance requirements
   - Document license obligations

3. **Maintenance Status**:
   - Check project maintenance activity
   - Review community support
   - Analyze bus factor risks
   - Plan replacement strategies

4. **Performance Impact**:
   - Analyze dependency bundle sizes
   - Check runtime performance impact
   - Review loading and initialization times
   - Identify optimization opportunities

Provide a dependency health report with upgrade recommendations.
```

## 🎨 **Team Workflow Prompts**

### **Code Review Standards Prompt**
```
Establish and review code review standards:

1. **Review Checklist**:
   - Create comprehensive review checklist
   - Define review criteria and standards
   - Establish review process guidelines
   - Plan reviewer assignment strategy

2. **Quality Gates**:
   - Define minimum review requirements
   - Set automated check requirements
   - Establish merge criteria
   - Plan rollback procedures

3. **Knowledge Sharing**:
   - Create review documentation
   - Plan knowledge transfer sessions
   - Establish mentoring procedures
   - Create learning resources

4. **Process Improvement**:
   - Analyze review effectiveness
   - Collect feedback from team
   - Identify bottlenecks
   - Plan process optimizations

Create a code review playbook for the team.
```

### **Development Environment Setup Prompt**
```
Optimize development environment and onboarding:

1. **Environment Consistency**:
   - Review development setup procedures
   - Check environment reproducibility
   - Verify dependency management
   - Test onboarding documentation

2. **Tooling & Automation**:
   - Review developer tooling effectiveness
   - Check automation coverage
   - Verify IDE configurations
   - Plan productivity improvements

3. **Documentation Quality**:
   - Review setup documentation accuracy
   - Check troubleshooting guides
   - Verify environment requirements
   - Plan documentation improvements

4. **Onboarding Experience**:
   - Test new developer onboarding
   - Collect onboarding feedback
   - Identify common pain points
   - Plan experience improvements

Create an optimized development environment guide.
```

## 📊 **Metrics & Analytics Prompts**

### **Business Metrics Analysis Prompt**
```
Analyze business and technical metrics:

1. **Performance Metrics**:
   - Review application performance trends
   - Analyze user experience metrics
   - Check system reliability metrics
   - Monitor business KPI impact

2. **User Analytics**:
   - Analyze user behavior patterns
   - Review feature usage statistics
   - Check conversion funnel metrics
   - Monitor user satisfaction scores

3. **Technical Health**:
   - Review system error rates
   - Analyze deployment success rates
   - Check infrastructure costs
   - Monitor technical debt metrics

4. **Predictive Analysis**:
   - Forecast capacity requirements
   - Predict maintenance needs
   - Analyze growth projections
   - Plan resource allocation

Create a comprehensive metrics dashboard with insights.
```

### **Cost Optimization Prompt**
```
Analyze and optimize infrastructure and operational costs:

1. **Resource Utilization**:
   - Review infrastructure usage patterns
   - Identify underutilized resources
   - Analyze peak vs. average usage
   - Check resource allocation efficiency

2. **Cost Analysis**:
   - Break down costs by service/component
   - Compare costs vs. business value
   - Identify cost optimization opportunities
   - Plan budget allocation strategies

3. **Efficiency Improvements**:
   - Suggest resource consolidation
   - Plan auto-scaling implementations
   - Review pricing model optimization
   - Analyze alternative solutions

4. **ROI Assessment**:
   - Calculate infrastructure ROI
   - Analyze feature development costs
   - Review operational efficiency
   - Plan investment priorities

Provide a cost optimization roadmap with savings projections.
```

## 🚀 **Advanced Analysis Prompts**

### **Scalability Assessment Prompt**
```
Conduct a comprehensive scalability analysis:

1. **Current Capacity**:
   - Analyze current system limits
   - Review bottleneck identification
   - Check scaling mechanisms
   - Test load handling capabilities

2. **Growth Planning**:
   - Model growth scenarios
   - Plan scaling strategies
   - Identify infrastructure requirements
   - Estimate scaling costs

3. **Architecture Evolution**:
   - Review microservices readiness
   - Plan service decomposition
   - Analyze data partitioning needs
   - Design caching strategies

4. **Implementation Roadmap**:
   - Prioritize scaling initiatives
   - Plan phased implementations
   - Create scaling playbooks
   - Establish monitoring protocols

Create a scalability roadmap with milestone targets.
```

### **Innovation Opportunity Prompt**
```
Identify innovation and modernization opportunities:

1. **Technology Assessment**:
   - Review emerging technology trends
   - Analyze adoption opportunities
   - Check competitive advantages
   - Plan technology experiments

2. **Process Innovation**:
   - Review development workflows
   - Identify automation opportunities
   - Plan efficiency improvements
   - Create innovation frameworks

3. **User Experience Enhancement**:
   - Analyze user journey improvements
   - Review interface modernization
   - Plan accessibility enhancements
   - Create experience innovations

4. **Strategic Planning**:
   - Align with business objectives
   - Plan innovation investments
   - Create experimentation frameworks
   - Establish success metrics

Provide an innovation roadmap with proof-of-concept plans.
```

## 📋 **Usage Guidelines**

### **How to Use These Prompts**

1. **Select Appropriate Prompt**: Choose based on current needs and schedule
2. **Customize Context**: Adapt prompts to your specific project and domain
3. **Set Clear Scope**: Define boundaries for analysis to get focused results
4. **Follow Up**: Use results to create actionable todos and improvement plans

### **Prompt Scheduling Recommendations**

- **Daily**: Health Check (rotating focus areas)
- **Weekly**: Architecture Review or specialized analysis
- **Monthly**: Security Audit and Dependency Audit
- **Quarterly**: Scalability Assessment and Innovation Opportunities
- **As Needed**: Pre/Post Development, specific domain analysis

### **Integration with Development Workflow**

1. **Sprint Planning**: Use assessment prompts to inform planning
2. **Code Reviews**: Apply quality prompts during review process
3. **Retrospectives**: Use analysis results for improvement planning
4. **Incident Response**: Apply troubleshooting prompts during incidents

### **Continuous Improvement**

- **Track Results**: Monitor improvement metrics over time
- **Refine Prompts**: Update prompts based on effectiveness
- **Share Learnings**: Document insights for team knowledge sharing
- **Automate Where Possible**: Create automated checks from manual analysis

**Remember**: These prompts are starting points. Adapt them to your specific context, technology stack, and business requirements for maximum effectiveness.