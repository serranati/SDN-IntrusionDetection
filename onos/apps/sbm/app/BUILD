COMPILE_DEPS = CORE_DEPS + KRYO + CLI + JACKSON + [
    "//core/store/serializers:onos-core-serializers",
    "//core/store/primitives:onos-core-primitives",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.sbm"],
    deps = COMPILE_DEPS,
)
