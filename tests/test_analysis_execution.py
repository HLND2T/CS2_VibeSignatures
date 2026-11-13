import unittest

from analysis_execution import (
    AnalysisExecutionState,
    EdgeType,
    ExecutionEdge,
    ExecutionStage,
    ExecutionReason,
    build_stage_id,
    build_job_id,
    build_task_id,
    is_valid_task_transition,
    ExecutionJob,
    ExecutionNode,
    ExecutionPlan,
    PlanNodeType,
    TaskStatus,
)


class TestAnalysisExecutionState(unittest.TestCase):
    def state(self):
        plan = ExecutionPlan(
            jobs=[ExecutionJob("job", "stage", 0, "server", "windows", None)],
            nodes=[ExecutionNode("job/skill", "job", "stage", "skill", PlanNodeType.SKILL, 0, 0)],
        )
        return AnalysisExecutionState("run-1", plan)

    def test_preserves_terminal_evidence_and_sorted_output_sets(self):
        state = self.state()
        state.record_task_status("job/skill", TaskStatus.RUNNING, attempted=True)
        state.record_output_attempts("job/skill", ["b.yaml", "a.yaml", "b.yaml"])
        state.record_output_produced("job/skill", ["a.yaml"])
        state.record_task_status(
            "job/skill",
            TaskStatus.FAILED,
            reason="invalid_output",
            error="bad output",
            payload={"produced_outputs": ["a.yaml"]},
        )
        state.abort_pending("upstream_aborted")
        self.assertEqual(
            {
                "task_id": "job/skill",
                "status": "failed",
                "attempted": True,
                "reason": "invalid_output",
                "error": "bad output",
                "payload": {"produced_outputs": ["a.yaml"]},
                "attempted_outputs": ["a.yaml", "b.yaml"],
                "produced_outputs": ["a.yaml"],
            },
            state.task_record("job/skill"),
        )
        self.assertEqual("aborted", state.task_record("job")["status"])
        self.assertEqual(1, state.summary()["failed"])
        self.assertEqual(1, state.summary()["total"])

    def test_skipped_tasks_are_not_attempted_and_ignore_late_transitions(self):
        state = self.state()
        state.record_task_status("job/skill", TaskStatus.SKIPPED, reason="existing_outputs")
        state.record_task_status("job/skill", TaskStatus.RUNNING, attempted=True)
        record = state.task_record("job/skill")
        self.assertEqual("skipped", record["status"])
        self.assertEqual("existing_outputs", record["reason"])
        self.assertFalse(record["attempted"])

    def test_round_trips_worker_records_with_and_without_an_attempt(self):
        for attempted in (False, True):
            with self.subTest(attempted=attempted):
                record = {
                    "task_id": "job/skill",
                    "status": "succeeded",
                    "attempted": attempted,
                    "reason": None,
                    "error": None,
                    "payload": {},
                    "attempted_outputs": ["a.yaml"],
                    "produced_outputs": ["a.yaml"],
                }
                state = self.state()
                state.import_task_record(record)
                self.assertEqual(record, state.task_record("job/skill"))

    def test_rejects_worker_records_for_unknown_tasks(self):
        with self.assertRaisesRegex(ValueError, "Unknown worker task"):
            self.state().import_task_record({"task_id": "foreign"})


class TestExecutionModels(unittest.TestCase):
    def test_builds_stable_execution_identifiers(self) -> None:
        stage_id = build_stage_id(8, "engine")
        job_id = build_job_id(stage_id, "windows")

        self.assertEqual("stage-0008-engine", stage_id)
        self.assertEqual("stage-0008-engine-windows", job_id)
        self.assertEqual(
            "stage-0008-engine-windows/find-target",
            build_task_id(job_id, "find-target"),
        )

    def test_rejects_invalid_execution_identifier_parts(self) -> None:
        with self.assertRaises(ValueError):
            build_stage_id(-1, "engine")
        with self.assertRaises(ValueError):
            build_job_id("stage-0001-engine", "")
        with self.assertRaises(ValueError):
            build_task_id("stage-0001-engine-windows", "nested/task")

    def test_status_transitions_are_idempotent_and_terminal(self) -> None:
        self.assertTrue(is_valid_task_transition(TaskStatus.PENDING, TaskStatus.RUNNING))
        self.assertTrue(is_valid_task_transition(TaskStatus.RUNNING, TaskStatus.SUCCEEDED))
        self.assertTrue(is_valid_task_transition(TaskStatus.RUNNING, TaskStatus.SKIPPED))
        self.assertTrue(is_valid_task_transition(TaskStatus.SUCCEEDED, TaskStatus.SUCCEEDED))
        self.assertFalse(is_valid_task_transition(TaskStatus.SUCCEEDED, TaskStatus.RUNNING))

    def test_execution_plan_serializes_local_models(self) -> None:
        stage = ExecutionStage(
            id="stage-0000-engine",
            stage_index=0,
            module_name="engine",
            description="Engine analysis stage",
        )
        job = ExecutionJob(
            id="stage-0000-engine-windows",
            stage_id=stage.id,
            stage_index=0,
            module_name="engine",
            platform="windows",
            binary_path="bin/14141/engine/engine2.dll",
        )
        node = ExecutionNode(
            id=f"{job.id}/find-target",
            job_id=job.id,
            stage_id=stage.id,
            name="find-target",
            node_type=PlanNodeType.SKILL,
            order=0,
            layer=0,
            description="Locate the target function",
            data={"status": TaskStatus.PENDING},
        )
        plan = ExecutionPlan(
            stages=[stage],
            jobs=[job],
            nodes=[node],
            edges=[
                ExecutionEdge(
                    source=stage.id,
                    target=job.id,
                    edge_type=EdgeType.STAGE_ORDER,
                )
            ],
            warnings=[ExecutionReason.GRAPH_INVALID],
        )

        payload = plan.to_dict()

        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("Engine analysis stage", payload["stages"][0]["description"])
        self.assertEqual("skill", payload["nodes"][0]["node_type"])
        self.assertEqual("Locate the target function", payload["nodes"][0]["description"])
        self.assertEqual("pending", payload["nodes"][0]["data"]["status"])
        self.assertEqual("stage_order", payload["edges"][0]["edge_type"])
        self.assertEqual(["graph_invalid"], payload["warnings"])
