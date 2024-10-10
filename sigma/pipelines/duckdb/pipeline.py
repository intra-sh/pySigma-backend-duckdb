from typing import Union, Optional

from sigma.modifiers import SigmaStartswithModifier, SigmaEndswithModifier
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, DetectionItemTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, RuleProcessingCondition, DetectionItemProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem

# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

# Decide which rules should be converted vs skipped

class RuleContainsKeywordCondition(RuleProcessingCondition):
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        if not rule.detection:
            return False

        for detection in rule.detection.detections.values():
            if self.find_detection_item(detection):
                return True
        return False

    def find_detection_item(self, detection : Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        if isinstance(detection, SigmaDetection):
            for detection_item in detection.detection_items:
                if self.find_detection_item(detection_item):
                    return True
        elif isinstance(detection, SigmaDetectionItem):
            if detection.field is None:
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False

def duckdb_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="DuckDB Pipeline",
        allowed_backends=frozenset(["duckdb"]),
        priority=50,
        items=[
            ProcessingItem(
                identifier="duckdb_keyword_conditions",
                transformation=DetectionItemFailureTransformation("Keyword conditions are not supported by the DuckDB backend"),
                rule_conditions=[RuleContainsKeywordCondition()],
            ),
        ],
    )
