package org.jenkinsci.plugins.codesonar.conditions;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.Result;
import java.util.List;
import org.jenkinsci.plugins.codesonar.CodeSonarBuildAction;
import org.jenkinsci.plugins.codesonar.models.CodeSonarBuildActionDTO;
import org.jenkinsci.plugins.codesonar.models.analysis.Alert;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 *
 * @author Andrius
 */
public class YellowAlertLimitCondition extends Condition {
    private static final String NAME = "Yellow alerts";
   
    private int alertLimit = 1;
    private String warrantedResult = Result.UNSTABLE.toString();

    @DataBoundConstructor
    public YellowAlertLimitCondition(int alertLimit) {
        this.alertLimit = alertLimit;
    }
    
    @Override
    public Result validate(Run<?, ?> run, Launcher launcher, TaskListener listener) {
        CodeSonarBuildAction buildAction = run.getAction(CodeSonarBuildAction.class);
        if (buildAction == null) {
            return Result.SUCCESS;
        }

        CodeSonarBuildActionDTO buildActionDTO = buildAction.getBuildActionDTO();
        if (buildActionDTO == null) {
            return Result.SUCCESS;
        }
        
        List<Alert> yellowAlerts = buildActionDTO.getAnalysisActiveWarnings().getYellowAlerts();
        if (yellowAlerts.size() > alertLimit) {
            Result result = Result.fromString(warrantedResult);
            return result;
        }

        return Result.SUCCESS;
    }
    
    public int getAlertLimit() {
        return alertLimit;
    }

    @DataBoundSetter
    public void setAlertLimit(int alertLimit) {
        this.alertLimit = alertLimit;
    }
   
    public String getWarrantedResult() {
        return warrantedResult;
    }

    @DataBoundSetter
    public void setWarrantedResult(String warrantedResult) {
        this.warrantedResult = warrantedResult;
    }

    @Extension
    public static final class DescriptorImpl extends ConditionDescriptor<YellowAlertLimitCondition> {

        public DescriptorImpl() {
            load();
        }

        @Override
        public String getDisplayName() {
            return NAME;
        }
    }
}
