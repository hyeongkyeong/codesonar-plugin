/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.jenkinsci.plugins.codesonar.conditions;

import hudson.model.Descriptor;
import hudson.model.Result;
import hudson.util.ListBoxModel;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

/**
 *
 * @author andrius
 * @param <T>
 */
public abstract class ConditionDescriptor<T extends Condition> extends Descriptor<Condition> {

    public ListBoxModel doFillWarrantedResultItems() {
        ListBoxModel output = new ListBoxModel();
        output.add(new ListBoxModel.Option("Unstable", Result.UNSTABLE.toString()));
        output.add(new ListBoxModel.Option("Failed", Result.FAILURE.toString()));        
        return output;
    }

    @Override
    public Condition newInstance(StaplerRequest req, JSONObject formData) throws FormException {
        return super.newInstance(req, formData);
    }

}
