COMPILE_DEPS = CORE_DEPS  + CLI + JACKSON + REST +  [
    "//core/store/serializers:onos-core-serializers",
    "//core/store/primitives:onos-core-primitives",
    "//apps/sbm/app:onos-apps-sbm-app",
]

osgi_jar_with_tests(
    api_package = "org.onosproject.sbm.rest",
    api_version = "1.0",
    api_description = "REST API for Southbound MAC Monitor",
    api_title = "", # api_title = "Southbound MAC Monitor REST", -> this was the problem
    web_context = "/onos/v1/sbm",
    deps = COMPILE_DEPS,
)